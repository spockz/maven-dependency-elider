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
import org.eclipse.aether.RepositoryException;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformer;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.sisu.Priority;

/** Captures mediated graphs and applies fingerprint-bound node projections. */
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
          final String captureToken = java.util.UUID.randomUUID().toString();
          final ResolverArtifactGraphSnapshot before =
              ResolverArtifactGraphSnapshot.capture(
                  root, projectKey, planPresent, planFingerprint, planGeneration, 0L);
          final DependencyNode transformed =
              delegate == null ? root : delegate.transformGraph(root, context);
          applyPlanProjection(transformed, plan);
          final ResolverArtifactGraphSnapshot after =
              ResolverArtifactGraphSnapshot.capture(
                  transformed, projectKey, planPresent, planFingerprint, planGeneration, 0L);
          appendPair(decorated, before, after, projectKey, captureToken);
          return transformed;
        });
    return decorated;
  }

  private static void applyPlanProjection(
      final DependencyNode root, final ResolverArtifactPlan plan) throws RepositoryException {
    if (plan == null || plan.graphProjection() == null) {
      return;
    }
    final ResolverArtifactGraphProjection projection = plan.graphProjection();
    final String actualSource =
        ResolverArtifactGraphSnapshot.capture(root, "projection-source", false, null, 0L, 0L)
            .graphFingerprint();
    if (!projection.sourceFingerprint().equals(actualSource)) {
      throw new RepositoryException(
          "Resolver graph does not match the elision projection source fingerprint");
    }
    try {
      ResolverArtifactGraphProjection.apply(root, projection);
    } catch (final IllegalArgumentException exception) {
      throw new RepositoryException(
          "Cannot apply the validated elision graph projection", exception);
    }
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
    if (plan.graphProjection() != null) {
      fields.add(plan.graphProjection().captureToken());
      fields.add(plan.graphProjection().sourceFingerprint());
      fields.add(plan.graphProjection().projectedFingerprint());
      fields.addAll(plan.graphProjection().removedNodeIds());
    }
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

  private static void appendPair(
      final RepositorySystemSession session,
      final ResolverArtifactGraphSnapshot beforeSnapshot,
      final ResolverArtifactGraphSnapshot afterSnapshot,
      final String projectKey,
      final String captureToken) {
    final org.eclipse.aether.SessionData data = session.getData();
    while (true) {
      final Object current = data.get(SESSION_DATA_KEY);
      if (appendCaptureAttempt(
          data, current, beforeSnapshot, afterSnapshot, projectKey, captureToken)) {
        return;
      }
    }
  }

  private static boolean appendCaptureAttempt(
      final org.eclipse.aether.SessionData data,
      final Object current,
      final ResolverArtifactGraphSnapshot beforeSnapshot,
      final ResolverArtifactGraphSnapshot afterSnapshot,
      final String projectKey,
      final String captureToken) {
    final ResolverArtifactGraphSnapshotStore store =
        ResolverArtifactGraphSnapshotStore.fromPayload(current);
    final long generation = store.nextGeneration(projectKey);
    final ResolverArtifactGraphSnapshot before = beforeSnapshot.withCaptureGeneration(generation);
    final ResolverArtifactGraphSnapshot after = afterSnapshot.withCaptureGeneration(generation);
    final ResolverArtifactGraphCapturePair pair =
        new ResolverArtifactGraphCapturePair(
            projectKey,
            captureToken,
            generation,
            before.planPresent(),
            before.planFingerprint(),
            before.planGeneration(),
            before,
            after);
    final ResolverArtifactGraphSnapshotStore updated = store.append(pair);
    return updated.equals(store) || data.set(SESSION_DATA_KEY, current, updated.toPayload());
  }
}
