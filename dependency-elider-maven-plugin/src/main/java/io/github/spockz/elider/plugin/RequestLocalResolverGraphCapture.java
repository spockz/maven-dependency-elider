/* WHY: Captures one detached Resolver graph without sharing plugin session state. */

package io.github.spockz.elider.plugin;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.eclipse.aether.DefaultRepositoryCache;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.DefaultSessionData;
import org.eclipse.aether.RepositoryException;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformationContext;
import org.eclipse.aether.collection.DependencyGraphTransformer;
import org.eclipse.aether.graph.DependencyNode;

/** Owns the request-local session and the pair from its single graph transform. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class RequestLocalResolverGraphCapture {
  /** Project identity attached to each captured graph snapshot. */
  private final String projectKey;

  /** Distinguishes this capture token from shared lifecycle graph observations. */
  private final String captureToken = UUID.randomUUID().toString();

  /** Stores the one successful before/after pair. */
  private final AtomicReference<ResolverArtifactGraphCapturePair> capturedPair =
      new AtomicReference<>();

  /** Marks entry before any graph callback or delegate work begins. */
  private final AtomicBoolean entered = new AtomicBoolean();

  /** Prevents evidence from surviving any failed or repeated callback. */
  private final AtomicBoolean invalid = new AtomicBoolean();

  private RequestLocalResolverGraphCapture(final String projectKey) {
    this.projectKey = projectKey;
  }

  static Request create(final RepositorySystemSession baseSession, final String projectKey) {
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession(baseSession);
    session.setData(new DefaultSessionData());
    session.setCache(new DefaultRepositoryCache());
    session.setWorkspaceReader(
        EliderRepositorySessionDecorator.withoutPlannedReplacements(
            baseSession.getWorkspaceReader()));
    final Map<String, Object> properties =
        new ConcurrentHashMap<>(baseSession.getConfigProperties());
    properties.put(MavenOriginalInputAudit.AUDIT_MODE_CONFIG_KEY, Boolean.TRUE);
    session.setConfigProperties(properties);
    final RequestLocalResolverGraphCapture capture =
        new RequestLocalResolverGraphCapture(projectKey);
    session.setDependencyGraphTransformer(
        capture.wrapper(baseSession.getDependencyGraphTransformer()));
    return new Request(session, capture);
  }

  private DependencyGraphTransformer wrapper(final DependencyGraphTransformer original) {
    return (root, context) -> transform(root, context, original);
  }

  private DependencyNode transform(
      final DependencyNode root,
      final DependencyGraphTransformationContext context,
      final DependencyGraphTransformer original)
      throws RepositoryException {
    if (!entered.compareAndSet(false, true)) {
      return invalidate("Resolver transformed more than one graph in one request");
    }
    if (!MavenOriginalInputAudit.isAuditMode(context.getSession())) {
      return invalidate("Resolver did not retain the request-local audit marker");
    }
    final TransformResult result = transformOnce(root, context, original);
    if (result.transformed() == null) {
      return invalidate("Resolver graph transformer returned no graph");
    }
    capturedPair.set(
        new ResolverArtifactGraphCapturePair(
            projectKey, captureToken, 1L, false, null, 0L, result.before(), result.after()));
    return result.transformed();
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private TransformResult transformOnce(
      final DependencyNode root,
      final DependencyGraphTransformationContext context,
      final DependencyGraphTransformer original)
      throws RepositoryException {
    try {
      final ResolverArtifactGraphSnapshot before = snapshot(root);
      final DependencyNode transformed =
          original == null ? root : original.transformGraph(root, context);
      final ResolverArtifactGraphSnapshot after =
          transformed == null ? null : snapshot(transformed);
      return new TransformResult(transformed, before, after);
    } catch (final RepositoryException exception) {
      invalid.set(true);
      throw exception;
    } catch (final RuntimeException exception) {
      invalid.set(true);
      throw new RepositoryException("Resolver graph capture failed", exception);
    }
  }

  private ResolverArtifactGraphSnapshot snapshot(final DependencyNode root) {
    return ResolverArtifactGraphSnapshot.capture(root, projectKey, false, null, 0L, 1L);
  }

  private DependencyNode invalidate(final String message) throws RepositoryException {
    invalid.set(true);
    throw new RepositoryException(message);
  }

  ResolverArtifactGraphCapturePair pair() {
    return invalid.get() ? null : capturedPair.get();
  }

  private record TransformResult(
      DependencyNode transformed,
      ResolverArtifactGraphSnapshot before,
      ResolverArtifactGraphSnapshot after) {}

  record Request(
      DefaultRepositorySystemSession session, RequestLocalResolverGraphCapture graphCapture) {}
}
