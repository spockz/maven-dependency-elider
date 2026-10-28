// WHY: Publishes detached trim paths in Maven session data for the later resolver decorator.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.SessionData;

/** Builds and publishes the current project's detached retained-JAR paths. */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.UseConcurrentHashMap"})
final class ResolverArtifactPlanPublisher {
  /** Shared key containing only the versioned, classloader-neutral session payload. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static final String SESSION_DATA_KEY = "io.github.spockz.elider.resolver.artifact-plans.v1";

  private ResolverArtifactPlanPublisher() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void publish(
      final MavenSession session,
      final MavenProject project,
      final List<ArtifactTrimRecord> trimRecords)
      throws IOException {
    publish(session, project, trimRecords, null);
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  // Package scope keeps publication inside the Maven resolver adapter.
  static void publish(
      final MavenSession session,
      final MavenProject project,
      final List<ArtifactTrimRecord> trimRecords,
      final ResolverArtifactGraphProjection graphProjection)
      throws IOException {
    if (trimRecords.isEmpty() && !hasPublishingContext(session, project)) {
      return;
    }
    final ResolverArtifactPlan plan = createPlan(project, trimRecords, graphProjection);
    if (session == null || session.getRepositorySession() == null) {
      throw new IOException("Cannot publish resolver plan without a repository session");
    }
    final SessionData data = session.getRepositorySession().getData();
    while (true) {
      final Object current = data.get(SESSION_DATA_KEY);
      final ResolverArtifactPlanStore store = ResolverArtifactPlanStore.fromPayload(current);
      if (data.set(SESSION_DATA_KEY, current, store.withPlan(plan).toPayload())) {
        return;
      }
    }
  }

  private static boolean hasPublishingContext(
      final MavenSession session, final MavenProject project) {
    return session != null
        && session.getRepositorySession() != null
        && project != null
        && project.getBasedir() != null;
  }

  private static ResolverArtifactPlan createPlan(
      final MavenProject project,
      final List<ArtifactTrimRecord> trimRecords,
      final ResolverArtifactGraphProjection graphProjection)
      throws IOException {
    if (project == null || project.getBasedir() == null) {
      throw new IOException("Cannot publish resolver plan without project base directory");
    }
    final ResolverArtifactPlan.ProjectIdentity projectIdentity = projectIdentity(project);
    final Map<ResolverArtifactPlan.ArtifactIdentity, ResolverArtifactPlan.Replacement>
        replacements = new LinkedHashMap<>();
    for (final ArtifactTrimRecord record : trimRecords) {
      final PlanEntry entry = replacement(record);
      if (replacements.putIfAbsent(entry.identity(), entry.replacement()) != null) {
        throw new IOException(
            "Duplicate retained artifact replacement identity: " + entry.identity());
      }
    }
    return new ResolverArtifactPlan(projectIdentity, replacements, graphProjection);
  }

  private static PlanEntry replacement(final ArtifactTrimRecord record) throws IOException {
    final Path path = record.trimmedPath().toAbsolutePath().normalize();
    if (!Files.isRegularFile(path)) {
      throw new IOException("Validated retained artifact path is no longer a file: " + path);
    }
    if (!record.trimmedSha256().equals(ArtifactFileDigest.sha256(path))) {
      throw new IOException("Validated retained artifact digest changed: " + path);
    }
    final ArtifactCoordinate coordinate = Objects.requireNonNull(record.coordinate());
    if (!"jar".equals(coordinate.type())) {
      throw new IOException(
          "Only retained JAR replacements are supported by the resolver plan: " + coordinate);
    }
    final ResolverArtifactPlan.ArtifactIdentity identity =
        new ResolverArtifactPlan.ArtifactIdentity(
            coordinate.groupId(),
            coordinate.artifactId(),
            coordinate.version(),
            coordinate.type(),
            coordinate.classifier());
    return new PlanEntry(
        identity, new ResolverArtifactPlan.Replacement(path, record.trimmedSha256()));
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static ResolverArtifactPlan.ProjectIdentity projectIdentity(final MavenProject project)
      throws IOException {
    try {
      return new ResolverArtifactPlan.ProjectIdentity(
          project.getBasedir().toPath(),
          project.getGroupId(),
          project.getArtifactId(),
          project.getVersion());
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Cannot publish resolver plan without project GAV", exception);
    }
  }

  private record PlanEntry(
      ResolverArtifactPlan.ArtifactIdentity identity,
      ResolverArtifactPlan.Replacement replacement) {}
}
