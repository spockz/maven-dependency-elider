// WHY: Keeps exclusion recommendations advisory and bound to frozen pre-injection declarations.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Persisted findings and frozen provenance. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
record ExclusionReview(
    boolean available,
    String unavailableReason,
    Map<String, Object> snapshot,
    List<Candidate> candidates,
    List<ExclusionRecommendations.Declaration> management) {
  ExclusionReview {
    Objects.requireNonNull(unavailableReason, "unavailableReason");
    candidates = List.copyOf(candidates);
    management = List.copyOf(management);
    if (available) {
      if (!unavailableReason.isEmpty() || snapshot == null) {
        throw new IllegalArgumentException("Available exclusion review requires a snapshot");
      }
      final ExclusionRecommendations.Snapshot decoded = ExclusionProvenancePayload.decode(snapshot);
      validateOrdinals(decoded.dependencies());
      validateOrdinals(decoded.management());
      snapshot = ExclusionProvenancePayload.encode(decoded);
      final ExclusionRecommendations.Result result = ExclusionRecommendations.collect(decoded);
      if (!candidates.equals(candidates(result)) || !management.equals(result.management())) {
        throw new IllegalArgumentException("Exclusion findings do not match the frozen snapshot");
      }
    } else if (unavailableReason.isBlank()
        || snapshot != null
        || !candidates.isEmpty()
        || !management.isEmpty()) {
      throw new IllegalArgumentException("Unavailable exclusion review must include only a reason");
    }
  }

  static ExclusionReview unavailable(final String reason) {
    return new ExclusionReview(false, reason, null, List.of(), List.of());
  }

  static ExclusionReview from(final ExclusionRecommendations.Snapshot snapshot) {
    final ExclusionRecommendations.Result result = ExclusionRecommendations.collect(snapshot);
    return new ExclusionReview(
        true,
        "",
        ExclusionProvenancePayload.encode(snapshot),
        candidates(result),
        result.management());
  }

  static ExclusionReview capture(final MavenProject project, final MavenSession session)
      throws IOException {
    if (session == null || session.getRepositorySession() == null) {
      return unavailable("No pre-injection declaration capture is available");
    }
    final BanishedDependencyOriginalModel original;
    try {
      original =
          BanishedDependencyCaptureStore.fromPayload(
                  EliderPreparationState.sessionData(session)
                      .get(BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY))
              .find(BanishedDependencyOriginalModel.projectIdentity(project));
    } catch (final IllegalArgumentException | IllegalStateException exception) {
      throw new IOException("Cannot read pre-injection exclusion provenance", exception);
    }
    if (original == null) {
      return unavailable("No pre-injection declaration capture is available");
    }
    final BanishedDependencyOriginalModel current;
    try {
      current =
          BanishedDependencyOriginalModel.capture(
              project, original.executions(), original.banishedDependencies());
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Cannot verify pre-injection exclusion provenance", exception);
    }
    if (!original.matchesCurrentModel(current)) {
      return unavailable("The dependency model changed after its pre-injection capture");
    }
    return from(original.exclusionProvenance());
  }

  private static List<Candidate> candidates(final ExclusionRecommendations.Result result) {
    return result.candidates().stream()
        .map(
            candidate ->
                new Candidate(candidate.coordinate(), candidate.count(), candidate.declarations()))
        .toList();
  }

  private static void validateOrdinals(
      final List<ExclusionRecommendations.Declaration> declarations) {
    for (int index = 0; index < declarations.size(); index++) {
      if (declarations.get(index).reference().ordinal() != index) {
        throw new IllegalArgumentException("Exclusion declaration ordinals are not canonical");
      }
    }
  }

  record Candidate(
      ExclusionRecommendations.Coordinate coordinate,
      int count,
      List<ExclusionRecommendations.Observation> declarations) {
    Candidate {
      Objects.requireNonNull(coordinate, "coordinate");
      declarations = List.copyOf(declarations);
      if (count < 2 || count != declarations.size()) {
        throw new IllegalArgumentException("Exclusion candidate count is inconsistent");
      }
    }
  }
}
