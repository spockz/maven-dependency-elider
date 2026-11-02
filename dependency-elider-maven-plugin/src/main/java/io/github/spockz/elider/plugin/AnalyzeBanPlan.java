// WHY: Binds strict, nonpublishing Analyze bans to one detached Resolver inventory and graph.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.MavenAnalysisEvidence.RootEvidence;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.apache.maven.plugin.MojoFailureException;

/** One immutable, uncommitted ban decision for a detached Analyze request. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
record AnalyzeBanPlan(String contextFingerprint, List<Entry> entries) {
  AnalyzeBanPlan {
    entries = List.copyOf(entries);
  }

  static AnalyzeBanPlan empty() {
    return new AnalyzeBanPlan("none", List.of());
  }

  static AnalyzeBanPlan create(
      final MavenAnalysisResolutionContext context, final AnalysisOptions options)
      throws MojoFailureException {
    final BanishedDependencyPolicy.Resolution resolution =
        BanishedDependencyPolicy.resolve(
            options.retainedArtifacts(),
            options.banishedDependencies(),
            context.project().getDependencies(),
            options.trim().passThroughArtifacts(),
            context.artifacts().resolvedSnapshots(),
            context.artifacts().directSnapshots());
    if (!resolution.requested().isEmpty()
        && context.provenance() != AnalyzePrediction.Provenance.DETACHED_CURRENT_MODEL) {
      throw new MojoFailureException(
          "elide.banishedDependencies requires detached no-extension Analyze; active extension "
              + "requests remain fail-closed");
    }
    final List<Entry> entries =
        resolution.matches().stream()
            .map(
                match ->
                    new Entry(
                        match.dependency(),
                        match.artifacts().stream()
                            .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
                            .sorted()
                            .toList()))
            .toList();
    return new AnalyzeBanPlan(context.graphPairFingerprint(), entries);
  }

  boolean requested() {
    return !entries.isEmpty();
  }

  Set<ArtifactCoordinate> forcedAbsentAfterResolution() {
    final Set<ArtifactCoordinate> coordinates = new TreeSet<>();
    entries.forEach(entry -> coordinates.addAll(entry.artifacts()));
    return Set.copyOf(coordinates);
  }

  void verifyContext(final MavenAnalysisResolutionContext context) throws MojoFailureException {
    if (requested() && !contextFingerprint.equals(context.graphPairFingerprint())) {
      throw new MojoFailureException("Analyze ban plan does not match its detached Resolver graph");
    }
  }

  void verifyEvidence(final RootEvidence evidence) throws MojoFailureException {
    if (!requested()) {
      return;
    }
    final Set<String> suppliedClasses = new TreeSet<>();
    final Set<String> incomingDynamicClasses = new TreeSet<>();
    for (final ArtifactCoordinate coordinate : forcedAbsentAfterResolution()) {
      suppliedClasses.clear();
      incomingDynamicClasses.clear();
      evidence
          .index()
          .classesByArtifact()
          .forEach(
              (artifact, classes) -> {
                if (artifact.coordinate().equals(coordinate)) {
                  suppliedClasses.addAll(classes);
                }
              });
      rejectClassIntersection(
          coordinate, "runtime trace", suppliedClasses, evidence.trace().loadedClassesDotFormat());
      rejectClassIntersection(
          coordinate, "source attribution", suppliedClasses, evidence.sourceRequiredClasses());
      if (evidence.bytecodeScan().isPresent() && !evidence.bytecodeScan().get().complete()) {
        throw conflict(coordinate, "production bytecode evidence is incomplete");
      }
      rejectClassIntersection(
          coordinate,
          "production bytecode",
          suppliedClasses,
          evidence
              .bytecodeScan()
              .map(io.github.spockz.elider.scanner.BytecodeReferenceScan::referencedClasses)
              .orElse(Set.of()));
      evidence
          .dynamicRoots()
          .classRootsByDeclaringArtifact()
          .forEach(
              (source, classes) -> {
                if (!source.equals(coordinate)) {
                  incomingDynamicClasses.addAll(classes);
                }
              });
      rejectClassIntersection(
          coordinate, "dynamic metadata or provider", suppliedClasses, incomingDynamicClasses);
      if (evidence.dynamicRoots().resourceProvidersByDeclaringArtifact().entrySet().stream()
          .anyMatch(
              source ->
                  !source.getKey().equals(coordinate) && source.getValue().contains(coordinate))) {
        throw conflict(coordinate, "resource or provider metadata requires the artifact");
      }
    }
  }

  private static void rejectClassIntersection(
      final ArtifactCoordinate coordinate,
      final String origin,
      final Set<String> supplied,
      final Set<String> required)
      throws MojoFailureException {
    final Set<String> overlap = new TreeSet<>(supplied);
    overlap.retainAll(required);
    if (!overlap.isEmpty()) {
      throw conflict(coordinate, origin + " requires class " + overlap.iterator().next());
    }
  }

  private static MojoFailureException conflict(
      final ArtifactCoordinate coordinate, final String reason) {
    return new MojoFailureException(
        "elide.banishedDependencies conflicts with " + coordinate + ": " + reason);
  }

  ElisionDecision forceAbsent(final ElisionDecision decision) throws MojoFailureException {
    if (!requested()) {
      return decision;
    }
    final Set<ArtifactCoordinate> retained = new LinkedHashSet<>(decision.retainedArtifacts());
    final Set<ArtifactCoordinate> elided = new LinkedHashSet<>(decision.elidedArtifacts());
    for (final ArtifactCoordinate coordinate : forcedAbsentAfterResolution()) {
      if (!retained.remove(coordinate) && !elided.contains(coordinate)) {
        throw conflict(coordinate, "resolved artifact is missing from the raw decision");
      }
      elided.add(coordinate);
    }
    return new ElisionDecision(
        retained,
        elided,
        decision.retainedClassesPerArtifact(),
        decision.unusedClassesPerArtifact(),
        decision.elapsedNanos());
  }

  void verifyGraph(final EffectiveGraphPolicy.Evaluation evaluation) throws MojoFailureException {
    if (!requested()) {
      return;
    }
    if (evaluation.failClosed()) {
      throw new MojoFailureException(
          "Analyze ban cannot establish graph absence: " + evaluation.failClosedReason());
    }
    for (final ArtifactCoordinate coordinate : forcedAbsentAfterResolution()) {
      if (!evaluation.elidedArtifacts().contains(coordinate)) {
        throw conflict(coordinate, "Resolver graph protects or promotes the banned artifact");
      }
    }
  }

  void verifyNoPromotion(final Set<ArtifactCoordinate> newlyReached) throws MojoFailureException {
    for (final ArtifactCoordinate coordinate : forcedAbsentAfterResolution()) {
      if (newlyReached.contains(coordinate)) {
        throw conflict(coordinate, "retained bytecode, resources, or providers reach the artifact");
      }
    }
  }

  /** One normalized policy identity and its current resolved matches. */
  record Entry(BanishedDependency dependency, List<ArtifactCoordinate> artifacts) {
    Entry {
      artifacts = List.copyOf(artifacts);
    }

    boolean matched() {
      return !artifacts.isEmpty();
    }
  }
}
