// WHY: Audits original Maven inputs without changing live Resolver state.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.DefaultDependencyResolutionRequest;
import org.apache.maven.project.DependencyResolutionException;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.DefaultSessionData;
import org.eclipse.aether.RepositoryException;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformationContext;
import org.eclipse.aether.collection.DependencyGraphTransformer;
import org.eclipse.aether.graph.DependencyNode;

/** Resolves a detached inventory from frozen pre-injection project declarations. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired", "PMD.LawOfDemeter"})
// One audit binds the frozen Maven model to an isolated Resolver request.
final class MavenOriginalInputAudit {
  static final String HOOK_PRESENT_KEY = MavenOriginalInputAudit.class.getName() + ".hookPresent";
  static final String AUDIT_MODE_CONFIG_KEY =
      MavenOriginalInputAudit.class.getName() + ".auditMode";

  private MavenOriginalInputAudit() {}

  static void markHookPresent(final MavenSession session) {
    Objects.requireNonNull(session, "session");
    EliderPreparationState.sessionData(session).set(HOOK_PRESENT_KEY, Boolean.TRUE);
  }

  static boolean isAuditMode(final RepositorySystemSession session) {
    return session != null
        && Boolean.TRUE.equals(session.getConfigProperties().get(AUDIT_MODE_CONFIG_KEY));
  }

  static Inventory audit(
      final MavenProject liveProject,
      final MavenSession session,
      final ProjectDependenciesResolver resolver)
      throws IOException {
    Objects.requireNonNull(resolver, "resolver");
    final BanishedDependencyOriginalModel captured = requireCapture(liveProject, session);
    final MavenProject auditProject = MavenOriginalInputProject.reconstruct(liveProject, captured);
    final Resolution resolution = resolve(captured, auditProject, session, resolver);
    return MavenOriginalInputInventory.create(
        captured, resolution.projectKey(), resolution.result(), resolution.graphPair());
  }

  private static BanishedDependencyOriginalModel requireCapture(
      final MavenProject liveProject, final MavenSession session) throws IOException {
    Objects.requireNonNull(liveProject, "liveProject");
    Objects.requireNonNull(session, "session");
    if (!Boolean.TRUE.equals(EliderPreparationState.sessionData(session).get(HOOK_PRESENT_KEY))) {
      throw new IOException("Original-input audit requires the active lifecycle extension hook");
    }
    if (session.getRepositorySession() == null) {
      throw new IOException("Original-input audit requires a Maven Resolver session");
    }
    final BanishedDependencyOriginalModel captured =
        BanishedDependencyCaptureStore.fromPayload(
                EliderPreparationState.sessionData(session)
                    .get(BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY))
            .find(BanishedDependencyOriginalModel.projectIdentity(liveProject));
    if (captured == null) {
      throw new IOException("Original-input audit has no frozen project capture");
    }
    verifyCaptureSource(liveProject, captured);
    return captured;
  }

  private static void verifyCaptureSource(
      final MavenProject liveProject, final BanishedDependencyOriginalModel captured)
      throws IOException {
    final BanishedDependencyOriginalModel current;
    try {
      current =
          BanishedDependencyOriginalModel.capture(
              liveProject, captured.executions(), captured.banishedDependencies());
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Cannot verify the live project against its frozen capture", exception);
    }
    if (!captured.matchesCurrentModel(current)) {
      throw new IOException(
          "Live dependency model no longer matches its frozen pre-injection capture");
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Resolution resolve(
      final BanishedDependencyOriginalModel captured,
      final MavenProject auditProject,
      final MavenSession session,
      final ProjectDependenciesResolver resolver)
      throws IOException {
    final RepositorySystemSession baseSession = session.getRepositorySession();
    if (baseSession == null) {
      throw new IOException("Original-input audit requires a Maven Resolver session");
    }
    final DefaultRepositorySystemSession auditSession =
        new DefaultRepositorySystemSession(baseSession);
    auditSession.setData(new DefaultSessionData());
    final Map<String, Object> configProperties =
        new java.util.HashMap<>(baseSession.getConfigProperties());
    configProperties.put(AUDIT_MODE_CONFIG_KEY, Boolean.TRUE);
    auditSession.setConfigProperties(configProperties);
    final String projectKey = BanishedDependencyCaptureStore.projectKey(captured.project());
    final String captureToken = UUID.randomUUID().toString();
    final AtomicReference<ResolverArtifactGraphCapturePair> graphAudit = new AtomicReference<>();
    final DependencyGraphTransformer originalTransformer =
        baseSession.getDependencyGraphTransformer();
    auditSession.setDependencyGraphTransformer(
        (root, context) ->
            transformAuditGraph(
                root, context, originalTransformer, projectKey, captureToken, graphAudit));
    final DependencyResolutionResult result;
    try {
      result = resolver.resolve(new DefaultDependencyResolutionRequest(auditProject, auditSession));
    } catch (final DependencyResolutionException exception) {
      throw new IOException("Cannot resolve the original dependency model", exception);
    }
    final ResolverArtifactGraphCapturePair capturedGraphs = graphAudit.get();
    if (result == null) {
      throw new IOException("Original-input resolver returned no result");
    }
    return new Resolution(projectKey, result, capturedGraphs);
  }

  private static DependencyNode transformAuditGraph(
      final DependencyNode root,
      final DependencyGraphTransformationContext context,
      final DependencyGraphTransformer originalTransformer,
      final String projectKey,
      final String captureToken,
      final AtomicReference<ResolverArtifactGraphCapturePair> graphAudit)
      throws RepositoryException {
    final ResolverArtifactGraphSnapshot before =
        ResolverArtifactGraphSnapshot.capture(root, projectKey, false, null, 0L, 1L);
    final DependencyNode transformed =
        originalTransformer == null ? root : originalTransformer.transformGraph(root, context);
    if (transformed == null) {
      throw new RepositoryException("Original-input graph transformer returned no graph");
    }
    final ResolverArtifactGraphSnapshot after =
        ResolverArtifactGraphSnapshot.capture(transformed, projectKey, false, null, 0L, 1L);
    final ResolverArtifactGraphCapturePair pair =
        new ResolverArtifactGraphCapturePair(
            projectKey, captureToken, 1L, false, null, 0L, before, after);
    if (!graphAudit.compareAndSet(null, pair)) {
      throw new RepositoryException("Original-input resolver transformed more than one graph");
    }
    return transformed;
  }

  record Inventory(
      BanishedDependencyOriginalModel.ProjectIdentity project,
      String sourceFingerprint,
      ResolverArtifactGraphCapturePair graphPair,
      List<AuditArtifact> resolvedArtifacts,
      List<ArtifactCoordinate> directArtifacts,
      String fingerprint) {
    Inventory {
      Objects.requireNonNull(project, "project");
      Objects.requireNonNull(sourceFingerprint, "sourceFingerprint");
      Objects.requireNonNull(graphPair, "graphPair");
      if (graphPair.captureGeneration() != 1L
          || graphPair.planPresent()
          || graphPair.planGeneration() != 0L) {
        throw new IllegalArgumentException("Audit graph pair must be request-local and plan-free");
      }
      resolvedArtifacts =
          List.copyOf(Objects.requireNonNull(resolvedArtifacts, "resolvedArtifacts"));
      directArtifacts = List.copyOf(Objects.requireNonNull(directArtifacts, "directArtifacts"));
      final List<String> fields = new ArrayList<>();
      fields.add(BanishedDependencyCaptureStore.projectKey(project));
      fields.add(sourceFingerprint);
      fields.add(graphPair.before().graphFingerprint());
      fields.add(graphPair.after().graphFingerprint());
      appendCoordinates(fields, "direct", directArtifacts);
      appendArtifacts(fields, resolvedArtifacts);
      final String expected = MavenElisionGraphBinding.sha256(fields);
      if (fingerprint == null) {
        fingerprint = expected;
      } else if (!fingerprint.equals(expected)) {
        throw new IllegalArgumentException("Audit inventory fingerprint does not match its values");
      }
    }

    ResolverArtifactGraphSnapshot graphBeforeTransformation() {
      return graphPair.before();
    }

    ResolverArtifactGraphSnapshot graph() {
      return graphPair.after();
    }

    private static void appendCoordinates(
        final List<String> fields, final String label, final List<ArtifactCoordinate> values) {
      fields.add(label);
      fields.add(Integer.toString(values.size()));
      values.forEach(
          coordinate -> {
            fields.add(coordinate.groupId());
            fields.add(coordinate.artifactId());
            fields.add(coordinate.version());
            fields.add(coordinate.type());
            fields.add(coordinate.classifier());
            fields.add(coordinate.scope());
          });
    }

    private static void appendArtifacts(
        final List<String> fields, final List<AuditArtifact> values) {
      fields.add("resolved-artifacts");
      fields.add(Integer.toString(values.size()));
      values.forEach(
          artifact -> {
            appendCoordinates(fields, "resolved-coordinate", List.of(artifact.coordinate()));
            fields.add(artifact.filePath() == null ? "file-absent" : "file-present");
            if (artifact.filePath() != null) {
              fields.add(artifact.filePath());
            }
            fields.add(artifact.sha256() == null ? "digest-absent" : "digest-present");
            if (artifact.sha256() != null) {
              fields.add(artifact.sha256());
            }
          });
    }
  }

  private record Resolution(
      String projectKey,
      DependencyResolutionResult result,
      ResolverArtifactGraphCapturePair graphPair) {}

  /** Detached coordinate and byte identity for one resolved artifact. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record AuditArtifact(ArtifactCoordinate coordinate, String filePath, String sha256) {
    AuditArtifact {
      Objects.requireNonNull(coordinate, "coordinate");
      if (filePath != null && filePath.isBlank()) {
        throw new IllegalArgumentException("filePath must not be blank when present");
      }
      if (sha256 != null && !HexDigest.isLowercaseHex(sha256, 64)) {
        throw new IllegalArgumentException("sha256 must be a lowercase SHA-256 value");
      }
      if (sha256 != null && filePath == null) {
        throw new IllegalArgumentException("sha256 requires a filePath");
      }
    }
  }
}
