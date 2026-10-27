/* WHY: Captures Maven's mediated graph after existing Resolver transformers run. */

package io.github.spockz.elider.plugin;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.RepositorySessionDecorator;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformer;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.sisu.Priority;

/** Snapshots mediated graphs without changing the graph returned to Resolver. */
@SuppressWarnings("PMD.LawOfDemeter")
@Named("elider-mediated-graph-capture")
@Priority(9)
@Singleton
public final class EliderMediatedGraphCaptureDecorator implements RepositorySessionDecorator {
  /** Shared session key used by graph capture and its tests. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static final String SESSION_DATA_KEY = "io.github.spockz.elider.resolver.graph-snapshots.v1";

  /** Creates the indexed graph-capture session decorator. */
  public EliderMediatedGraphCaptureDecorator() {
    super();
  }

  @Override
  public RepositorySystemSession decorate(
      final MavenProject project, final RepositorySystemSession session) {
    if (project == null || project.getBasedir() == null || session == null) {
      return session;
    }
    final ResolverArtifactPlan.ProjectIdentity identity = projectIdentity(project);
    final String projectKey = ResolverArtifactPlanStore.projectKey(identity);
    final ResolverArtifactPlan plan = findPlan(session, identity);
    final boolean planPresent = plan != null;
    final String planFingerprint = planPresent ? planFingerprint(plan) : null;
    final long planGeneration = observePlan(session, projectKey, planPresent, planFingerprint);
    final DependencyGraphTransformer delegate = session.getDependencyGraphTransformer();
    final DefaultRepositorySystemSession decorated = new DefaultRepositorySystemSession(session);
    decorated.setDependencyGraphTransformer(
        (root, context) -> {
          final DependencyNode transformed =
              delegate == null ? root : delegate.transformGraph(root, context);
          appendSnapshot(
              decorated, transformed, projectKey, planPresent, planFingerprint, planGeneration);
          return transformed;
        });
    return decorated;
  }

  private static ResolverArtifactPlan.ProjectIdentity projectIdentity(final MavenProject project) {
    return new ResolverArtifactPlan.ProjectIdentity(
        project.getBasedir().toPath(),
        project.getGroupId(),
        project.getArtifactId(),
        project.getVersion());
  }

  private static ResolverArtifactPlan findPlan(
      final RepositorySystemSession session, final ResolverArtifactPlan.ProjectIdentity identity) {
    final Object payload = session.getData().get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY);
    return ResolverArtifactPlanStore.fromPayload(payload).find(identity);
  }

  private static String planFingerprint(final ResolverArtifactPlan plan) {
    final List<String> fields = new ArrayList<>();
    fields.add(ResolverArtifactPlanStore.projectKey(plan.project()));
    plan.replacements().entrySet().stream()
        .sorted(
            Map.Entry.comparingByKey(
                Comparator.comparing(EliderMediatedGraphCaptureDecorator::identityKey)))
        .forEach(
            entry -> {
              final ResolverArtifactPlan.ArtifactIdentity identity = entry.getKey();
              final ResolverArtifactPlan.Replacement replacement = entry.getValue();
              fields.add(identity.groupId());
              fields.add(identity.artifactId());
              fields.add(identity.version());
              fields.add(identity.extension());
              fields.add(identity.classifier());
              fields.add(replacement.path().toString());
              fields.add(replacement.sha256());
            });
    final StringBuilder canonical = new StringBuilder();
    fields.forEach(field -> canonical.append(field.length()).append(':').append(field));
    try {
      return java.util.HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256")
                  .digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }

  private static String identityKey(final ResolverArtifactPlan.ArtifactIdentity identity) {
    return List.of(
            identity.groupId(),
            identity.artifactId(),
            identity.version(),
            identity.extension(),
            identity.classifier())
        .stream()
        .map(value -> value.length() + ":" + value)
        .reduce("", String::concat);
  }

  private static long observePlan(
      final RepositorySystemSession session,
      final String projectKey,
      final boolean planPresent,
      final String planFingerprint) {
    final org.eclipse.aether.SessionData data = session.getData();
    while (true) {
      final Object current = data.get(SESSION_DATA_KEY);
      final ResolverArtifactGraphSnapshotStore store =
          ResolverArtifactGraphSnapshotStore.fromPayload(current);
      final ResolverArtifactGraphSnapshotStore.PlanObservation observation =
          store.observePlan(projectKey, planPresent, planFingerprint);
      final ResolverArtifactGraphSnapshotStore updated =
          store.withObservation(projectKey, observation);
      if (updated.equals(store) || data.set(SESSION_DATA_KEY, current, updated.toPayload())) {
        return observation.generation();
      }
    }
  }

  private static void appendSnapshot(
      final RepositorySystemSession session,
      final DependencyNode root,
      final String projectKey,
      final boolean planPresent,
      final String planFingerprint,
      final long planGeneration) {
    final org.eclipse.aether.SessionData data = session.getData();
    while (true) {
      final Object current = data.get(SESSION_DATA_KEY);
      final ResolverArtifactGraphSnapshotStore store =
          ResolverArtifactGraphSnapshotStore.fromPayload(current);
      final ResolverArtifactGraphSnapshot snapshot =
          ResolverArtifactGraphSnapshot.capture(
              root,
              projectKey,
              planPresent,
              planFingerprint,
              planGeneration,
              store.nextGeneration(projectKey));
      final ResolverArtifactGraphSnapshotStore updated = store.append(snapshot);
      if (updated.equals(store)) {
        return;
      }
      if (data.set(SESSION_DATA_KEY, current, updated.toPayload())) {
        return;
      }
    }
  }
}
