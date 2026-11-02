// WHY: Audits original Maven inputs without changing live Resolver state.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.DefaultDependencyResolutionRequest;
import org.apache.maven.project.DependencyResolutionException;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.eclipse.aether.RepositorySystemSession;

/** Resolves a detached inventory from frozen pre-injection project declarations. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
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

  static boolean hookPresent(final MavenSession session) {
    return session != null
        && Boolean.TRUE.equals(EliderPreparationState.sessionData(session).get(HOOK_PRESENT_KEY));
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
    final Inventory inventory =
        MavenOriginalInputInventory.create(
            captured, resolution.projectKey(), resolution.result(), resolution.graphPair());
    try {
      BanishedDependencyOriginalAuditPolicy.resolve(
          captured.banishedDependencies(), inventory.resolvedArtifacts());
    } catch (final org.apache.maven.plugin.MojoFailureException exception) {
      throw new IOException(
          "Original-input ban policy is unsupported: " + exception.getMessage(), exception);
    }
    return inventory;
  }

  static void verifyFresh(
      final Inventory inventory, final MavenProject liveProject, final MavenSession session)
      throws IOException {
    final BanishedDependencyOriginalModel captured = requireCapture(liveProject, session);
    if (!inventory.project().equals(captured.project())
        || !inventory.sourceFingerprint().equals(captured.sourceFingerprint())) {
      throw new IOException("Original-input audit no longer matches its frozen project capture");
    }
    for (final AuditArtifact artifact : inventory.resolvedArtifacts()) {
      verifyArtifactFresh(artifact);
    }
  }

  private static void verifyArtifactFresh(final AuditArtifact artifact) throws IOException {
    if (artifact.filePath() == null) {
      return;
    }
    final Path path = Path.of(artifact.filePath()).toAbsolutePath().normalize();
    if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
      throw new IOException("Original-input audit artifact is no longer readable: " + path);
    }
    if (!artifact.sha256().equals(ArtifactFileDigest.sha256(path))) {
      throw new IOException("Original-input audit artifact bytes changed: " + path);
    }
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

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
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
    final String projectKey = BanishedDependencyCaptureStore.projectKey(captured.project());
    final RequestLocalResolverGraphCapture.Request requestContext =
        RequestLocalResolverGraphCapture.create(baseSession, projectKey);
    final DependencyResolutionResult result;
    try {
      result =
          resolver.resolve(
              new DefaultDependencyResolutionRequest(auditProject, requestContext.session()));
    } catch (final DependencyResolutionException exception) {
      throw new IOException("Cannot resolve the original dependency model", exception);
    } catch (final RuntimeException exception) {
      throw new IOException(
          "Resolver failed while capturing the original dependency model", exception);
    }
    final ResolverArtifactGraphCapturePair capturedGraphs = requestContext.graphCapture().pair();
    if (result == null) {
      throw new IOException("Original-input resolver returned no result");
    }
    return new Resolution(projectKey, result, capturedGraphs);
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
            fields.add(artifact.mavenType());
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

  /** Resolver-extension coordinate, Maven type, and bytes for one resolved artifact. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record AuditArtifact(
      ArtifactCoordinate coordinate, String mavenType, String filePath, String sha256) {
    AuditArtifact {
      Objects.requireNonNull(coordinate, "coordinate");
      if (mavenType == null || mavenType.isBlank()) {
        throw new IllegalArgumentException("mavenType must not be blank");
      }
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
