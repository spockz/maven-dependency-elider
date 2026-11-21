/* WHY: Captures Maven's mediated graph after existing Resolver transformers
 * run. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.HexDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
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
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.TooManyMethods", "PMD.CompareObjectsWithEquals"})
@Named("elider-mediated-graph-capture")
@Priority(9)
@Singleton
public final class EliderMediatedGraphCaptureDecorator implements RepositorySessionDecorator {
  /** Shared session key used by graph capture and its tests. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static final String SESSION_DATA_KEY = "io.github.spockz.elider.resolver.graph-snapshots.v1";

  /** Cache of the most recently published immutable store keyed by SessionData. */
  private static final Map<org.eclipse.aether.SessionData, TrustedStore> TRUSTED_STORES =
      Collections.synchronizedMap(new WeakHashMap<>());

  private record TrustedStore(Object payload, ResolverArtifactGraphSnapshotStore store) {}

  /** Creates the indexed graph-capture session decorator. */
  public EliderMediatedGraphCaptureDecorator() {
    super();
  }

  @Override
  public RepositorySystemSession decorate(
      final MavenProject project, final RepositorySystemSession session) {
    if (MavenOriginalInputAudit.isAuditMode(session)) {
      return session;
    }
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
          if (MavenOriginalInputAudit.isAuditMode(context.getSession())) {
            return delegate == null ? root : delegate.transformGraph(root, context);
          }
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
    return HexDigest.sha256(canonical.toString());
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

  private static ResolverArtifactGraphSnapshotStore loadStore(
      final org.eclipse.aether.SessionData data, final Object current) {
    if (current == null) {
      return ResolverArtifactGraphSnapshotStore.empty();
    }
    final TrustedStore trusted = TRUSTED_STORES.get(data);
    if (trusted != null && trusted.payload() == current) {
      return trusted.store();
    }
    return ResolverArtifactGraphSnapshotStore.fromPayload(current);
  }

  private static boolean publishStore(
      final org.eclipse.aether.SessionData data,
      final Object current,
      final ResolverArtifactGraphSnapshotStore updated) {
    final Map<String, Object> nextPayload = updated.toPayload();
    if (data.set(SESSION_DATA_KEY, current, nextPayload)) {
      TRUSTED_STORES.put(data, new TrustedStore(nextPayload, updated));
      return true;
    }
    return false;
  }

  private static long observePlan(
      final RepositorySystemSession session,
      final String projectKey,
      final boolean planPresent,
      final String planFingerprint) {
    final org.eclipse.aether.SessionData data = session.getData();
    while (true) {
      final Object current = data.get(SESSION_DATA_KEY);
      final ResolverArtifactGraphSnapshotStore store = loadStore(data, current);
      final ResolverArtifactGraphSnapshotStore.PlanObservation observation =
          store.observePlan(projectKey, planPresent, planFingerprint);
      final ResolverArtifactGraphSnapshotStore updated =
          store.withObservation(projectKey, observation);
      if (updated == store || updated.equals(store) || publishStore(data, current, updated)) {
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
    final ResolverArtifactGraphSnapshotStore store = loadStore(data, current);
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
    return updated.equals(store) || publishStore(data, current, updated);
  }
}
