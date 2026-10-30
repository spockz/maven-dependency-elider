/* WHY: Selects a planless graph capture compatible with one Maven analysis operation. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystemSession;

/** Binds a unique graph pair to local inventory and operation evidence. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionGraphBinding {
  private MavenElisionGraphBinding() {
    throw new AssertionError("No instances");
  }

  static Result bind(
      final MavenProject project,
      final MavenElisionService.AnalysisOptions options,
      final List<MavenElisionService.ArtifactSnapshot> inventory,
      final ElisionDecision rawDecision,
      final TraceData trace,
      final Set<String> requiredRoots)
      throws IOException {
    final String projectKey = projectKey(project);
    final String inventoryFingerprint;
    try {
      inventoryFingerprint = ResolvedArtifactInventoryFingerprint.fingerprint(inventory);
    } catch (final IOException exception) {
      return failClosed(
          projectKey,
          rawDecision,
          null,
          null,
          "Resolved inventory cannot be fingerprinted: " + exception.getMessage());
    }
    final String operationFingerprint =
        operationFingerprint(
            project, options, inventoryFingerprint, trace, requiredRoots, rawDecision);
    if (!MavenElisionGraphInventory.matchesDecision(inventory, rawDecision)) {
      return failClosed(
          projectKey,
          rawDecision,
          inventoryFingerprint,
          operationFingerprint,
          "Resolved Maven inventory does not match the raw decision inventory");
    }
    if (!options.testResolutionContext()) {
      return failClosed(
          projectKey,
          rawDecision,
          inventoryFingerprint,
          operationFingerprint,
          "Maven goal does not establish TEST resolution context");
    }
    final Object payload = graphPayload(options);
    if (payload == null) {
      return failClosed(
          projectKey,
          rawDecision,
          inventoryFingerprint,
          operationFingerprint,
          "Maven resolver session is unavailable");
    }
    final ResolverArtifactGraphSnapshotStore store =
        ResolverArtifactGraphSnapshotStore.fromPayload(payload);
    final List<ResolverArtifactGraphCapturePair> projectPairs =
        store.capturePairs().getOrDefault(projectKey, List.of()).stream()
            .map(ResolverArtifactGraphCapturePair::fromPayload)
            .toList();
    final List<ResolverArtifactGraphCapturePair> compatiblePairs =
        projectPairs.stream()
            .filter(pair -> MavenElisionGraphInventory.matchesGraph(pair.after(), inventory))
            .toList();
    if (compatiblePairs.isEmpty()) {
      return failClosed(
          projectKey,
          rawDecision,
          inventoryFingerprint,
          operationFingerprint,
          "No plan-absent graph pair matches the complete resolved GAVCE/scope inventory");
    }
    final EffectiveGraphPolicy.Evaluation evaluation =
        EffectiveGraphPolicy.evaluate(compatiblePairs, projectKey, rawDecision);
    if (evaluation.failClosed()) {
      return new Result(evaluation, inventoryFingerprint, operationFingerprint, null);
    }
    final ResolverArtifactGraphCapturePair pair =
        compatiblePairs.stream()
            .filter(candidate -> candidate.captureToken().equals(evaluation.captureToken()))
            .findFirst()
            .orElseThrow(
                () -> new IllegalStateException("Selected graph capture pair disappeared"));
    return new Result(evaluation, inventoryFingerprint, operationFingerprint, pair);
  }

  static void verifyInventoryFingerprint(
      final List<MavenElisionService.ArtifactSnapshot> inventory, final String expectedFingerprint)
      throws IOException {
    ResolvedArtifactInventoryFingerprint.verifyFingerprint(inventory, expectedFingerprint);
  }

  private static Result failClosed(
      final String projectKey,
      final ElisionDecision rawDecision,
      final String inventoryFingerprint,
      final String operationFingerprint,
      final String reason) {
    return new Result(
        EffectiveGraphPolicy.failClosed(projectKey, rawDecision, reason),
        inventoryFingerprint,
        operationFingerprint,
        null);
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static String projectKey(final MavenProject project) {
    if (project.getBasedir() == null) {
      return "<missing-project-identity>";
    }
    if (project.getGroupId() == null
        || project.getArtifactId() == null
        || project.getVersion() == null) {
      return "<incomplete-project-identity>";
    }
    final ResolverArtifactPlan.ProjectIdentity identity =
        new ResolverArtifactPlan.ProjectIdentity(
            project.getBasedir().toPath(),
            project.getGroupId(),
            project.getArtifactId(),
            project.getVersion());
    return ResolverArtifactPlanStore.projectKey(identity);
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static Object graphPayload(final MavenElisionService.AnalysisOptions options) {
    final MavenSession session = options.session();
    if (session == null) {
      return null;
    }
    final RepositorySystemSession resolverSession = session.getRepositorySession();
    if (resolverSession == null) {
      return null;
    }
    return resolverSession.getData().get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY);
  }

  private static String operationFingerprint(
      final MavenProject project,
      final MavenElisionService.AnalysisOptions options,
      final String inventoryFingerprint,
      final TraceData trace,
      final Set<String> requiredRoots,
      final ElisionDecision decision)
      throws IOException {
    final List<String> fields = new ArrayList<>();
    fields.add(inventoryFingerprint);
    MavenCompilerSettings.releaseIdentity(project, options.session())
        .forEach(option -> fields.add("compiler-option=" + option));
    fields.add("runtime-release=" + Runtime.version().feature());
    fields.add(
        "java-home=" + Path.of(System.getProperty("java.home")).toAbsolutePath().normalize());
    fields.add(Boolean.toString(options.sourceRootsComplete()));
    fields.add(Boolean.toString(options.trimJars()));
    fields.add(options.mrjarStrategy());
    fields.add(Boolean.toString(options.failOnUnsupportedModuleInfo()));
    fields.add(Boolean.toString(options.failOnUnsupportedNativeImageArgs()));
    fields.addAll(sorted(options.allowedNativeImageArgs()));
    fields.addAll(sorted(options.excludedArtifacts()));
    fields.addAll(sorted(options.explicitTrimRoots()));
    fields.addAll(sorted(options.explicitPassThroughArtifacts()));
    fields.addAll(sorted(trace.loadedClassesDotFormat()));
    fields.addAll(sorted(requiredRoots));
    fields.addAll(sorted(decision.retainedArtifacts().stream().map(Object::toString).toList()));
    fields.addAll(sorted(decision.elidedArtifacts().stream().map(Object::toString).toList()));
    return sha256(fields);
  }

  private static List<String> sorted(final List<String> values) {
    return values == null ? List.of() : values.stream().sorted().toList();
  }

  private static List<String> sorted(final Set<String> values) {
    return values.stream().sorted().toList();
  }

  private static String sha256(final List<String> values) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (final String value : values) {
        final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(Integer.toString(bytes.length).getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) ':');
        digest.update(bytes);
      }
      return java.util.HexFormat.of().formatHex(digest.digest());
    } catch (final NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }

  record Result(
      EffectiveGraphPolicy.Evaluation evaluation,
      String inventoryFingerprint,
      String operationFingerprint,
      ResolverArtifactGraphCapturePair pair) {}
}
