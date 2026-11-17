/* WHY: Adapts Maven analysis inputs into provider evidence and prerequisite forecasts. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.applicability.PreconditionClassInventory;
import io.github.spockz.elider.applicability.PreconditionClassInventory.Provider;
import io.github.spockz.elider.applicability.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.applicability.PreconditionProof;
import io.github.spockz.elider.applicability.PreconditionProof.InventoryInspection;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Captures baseline providers and supported Analyze plan facts. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentSize",
  "PMD.CouplingBetweenObjects",
  "PMD.AvoidFieldNameMatchingMethodName"
})
final class MavenPreconditionPrediction {
  /** WHY: Maven test-scope entries are dependency metadata, not runtime class providers. */
  private static final String TEST_SCOPE = "test";

  @FunctionalInterface
  interface CaptureSupplier {
    Capture capture() throws IOException;
  }

  private MavenPreconditionPrediction() {}

  static Capture capture(
      final MavenProject project, final MavenSession session, final AnalyzePrediction prediction) {
    return capture(project, session, prediction, false);
  }

  static Capture capture(
      final MavenProject project,
      final MavenSession session,
      final AnalyzePrediction prediction,
      final boolean preconditionClassPathComplete) {
    final List<Provider> providers = new ArrayList<>();
    final List<String> failures = new ArrayList<>();
    final List<ElisionAnalysisModel.ArtifactSnapshot> runtimeArtifacts =
        prediction.inputArtifacts().stream()
            .filter(artifact -> !TEST_SCOPE.equals(artifact.coordinate().scope()))
            .toList();
    for (final ElisionAnalysisModel.ArtifactSnapshot artifact : runtimeArtifacts) {
      addProvider(artifact, providers, failures);
    }
    try {
      final MavenPreconditionProviderRoots.Capture roots =
          MavenPreconditionProviderRoots.capture(project, session, prediction.evidence(), false);
      providers.addAll(roots.providers());
      if (roots.incompleteDetail() != null) {
        failures.add(roots.incompleteDetail());
      }
    } catch (final IOException
        | UncheckedIOException
        | IllegalArgumentException
        | SecurityException failure) {
      failures.add("Could not capture application provider roots: " + message(failure));
    }
    Optional<InventoryInspection> inspection = Optional.empty();
    try {
      inspection =
          Optional.of(PreconditionProof.inspect(PreconditionClassInventory.complete(providers)));
    } catch (final IOException
        | UncheckedIOException
        | IllegalArgumentException
        | SecurityException failure) {
      failures.add("Could not inspect baseline providers: " + message(failure));
    }
    final String finalDetail = failures.isEmpty() ? null : String.join("; ", failures);
    final PreconditionClassInventory capturedBaseline =
        finalDetail == null
            ? PreconditionClassInventory.complete(providers)
            : PreconditionClassInventory.incomplete(providers, finalDetail);
    final Optional<InventoryInspection> proofInspection =
        preconditionClassPathComplete && finalDetail == null ? inspection : Optional.empty();
    return new Capture(prediction, capturedBaseline, inspection, proofInspection, finalDetail);
  }

  private static String message(final Exception failure) {
    return Objects.toString(failure.getMessage(), failure.getClass().getSimpleName());
  }

  private static void addProvider(
      final ElisionAnalysisModel.ArtifactSnapshot artifact,
      final List<Provider> providers,
      final List<String> failures) {
    try {
      providers.add(Provider.dependencyArchive(artifact.coordinate(), artifact.filePath()));
    } catch (final IOException
        | UncheckedIOException
        | IllegalArgumentException
        | SecurityException failure) {
      failures.add(
          "Could not inspect input artifact " + artifact.coordinate() + ": " + message(failure));
    }
  }

  private static String exactIdentity(final ArtifactCoordinate coordinate) {
    return coordinate.groupId()
        + ":"
        + coordinate.artifactId()
        + ":"
        + coordinate.type()
        + ":"
        + coordinate.classifier()
        + ":"
        + coordinate.version();
  }

  private static PrerequisitePrediction.MemberForecast unknown(
      final PrerequisiteClaim claim,
      final List<PrerequisitePrediction.ProviderForecast> providers,
      final String detail) {
    return new PrerequisitePrediction.MemberForecast(
        claim,
        PrerequisitePrediction.MemberState.UNKNOWN,
        PrerequisitePrediction.MemberReason.UNKNOWN,
        providers,
        Objects.toString(detail, "Baseline provider inventory is incomplete"));
  }

  static final class Capture {
    private final AnalyzePrediction prediction;
    private final PreconditionClassInventory baseline;
    private final Optional<InventoryInspection> inspection;
    private final Optional<InventoryInspection> proofInspection;
    private final String detail;

    private Capture(
        final AnalyzePrediction prediction,
        final PreconditionClassInventory baseline,
        final Optional<InventoryInspection> inspection,
        final Optional<InventoryInspection> proofInspection,
        final String detail) {
      this.prediction = Objects.requireNonNull(prediction, "prediction");
      this.baseline = Objects.requireNonNull(baseline, "baseline");
      this.inspection = Objects.requireNonNull(inspection, "inspection");
      this.proofInspection = Objects.requireNonNull(proofInspection, "proofInspection");
      this.detail = detail;
    }

    Optional<InventoryInspection> proofInspection() {
      return proofInspection;
    }

    PrerequisitePrediction predict(
        final ArtifactCoordinate candidate, final Collection<PrerequisiteGroup> selectedGroups) {
      final List<PrerequisitePrediction.GroupForecast> groups =
          selectedGroups.stream().sorted().map(this::forecastGroup).toList();
      return new PrerequisitePrediction(
          candidate, baseline.fingerprint(), prediction.operationFingerprint(), groups, detail);
    }

    private PrerequisitePrediction.GroupForecast forecastGroup(final PrerequisiteGroup group) {
      final List<PrerequisitePrediction.MemberForecast> members =
          group.members().stream().sorted().map(this::forecastMember).toList();
      final boolean disarmed =
          switch (group.operator()) {
            case ANY_OF ->
                members.stream()
                    .allMatch(
                        member -> member.state() == PrerequisitePrediction.MemberState.ABSENT);
            case ALL_OF ->
                members.stream()
                    .anyMatch(
                        member -> member.state() == PrerequisitePrediction.MemberState.ABSENT);
          };
      return new PrerequisitePrediction.GroupForecast(group, members, disarmed);
    }

    private PrerequisitePrediction.MemberForecast forecastMember(final PrerequisiteClaim claim) {
      if (inspection.isEmpty()) {
        return unknown(claim, List.of(), detail);
      }
      final List<Provider> owners =
          inspection.orElseThrow().providersForClass(claim.requiresClass());
      if (owners.isEmpty()) {
        return detail == null
            ? new PrerequisitePrediction.MemberForecast(
                claim,
                PrerequisitePrediction.MemberState.ABSENT,
                PrerequisitePrediction.MemberReason.ALREADY_ABSENT,
                List.of(),
                null)
            : unknown(claim, List.of(), detail);
      }
      final List<PrerequisitePrediction.ProviderForecast> planned =
          owners.stream().map(provider -> planProvider(provider, claim.requiresClass())).toList();
      if (planned.stream().anyMatch(PrerequisitePrediction.ProviderForecast::survives)) {
        return new PrerequisitePrediction.MemberForecast(
            claim,
            PrerequisitePrediction.MemberState.PRESENT,
            PrerequisitePrediction.MemberReason.PRESENT,
            planned,
            null);
      }
      if (detail != null) {
        return unknown(claim, planned, detail);
      }
      return new PrerequisitePrediction.MemberForecast(
          claim, PrerequisitePrediction.MemberState.ABSENT, absenceReason(planned), planned, null);
    }

    private PrerequisitePrediction.ProviderForecast planProvider(
        final Provider provider, final String className) {
      final PrerequisitePrediction.ProviderPlan plan =
          provider.kind() == ProviderKind.DEPENDENCY_ARCHIVE
              ? dependencyPlan(provider, className)
              : PrerequisitePrediction.ProviderPlan.RETAINED;
      return new PrerequisitePrediction.ProviderForecast(
          provider.kind(), provider.coordinate(), provider.path(), provider.sha256(), plan);
    }

    private PrerequisitePrediction.ProviderPlan dependencyPlan(
        final Provider provider, final String className) {
      final boolean retained = containsExact(prediction.retainedArtifacts(), provider.coordinate());
      final boolean elided = containsExact(prediction.wouldElideArtifacts(), provider.coordinate());
      if (retained == elided) {
        throw new IllegalArgumentException(
            "Analyze plan must classify dependency provider exactly once: "
                + provider.coordinate());
      }
      if (elided) {
        return PrerequisitePrediction.ProviderPlan.ELIDED;
      }
      if (removedByPlan(provider.coordinate(), prediction.plannedTrims()).contains(className)) {
        return PrerequisitePrediction.ProviderPlan.TRIMMED_CLASS;
      }
      return PrerequisitePrediction.ProviderPlan.RETAINED;
    }

    private boolean containsExact(
        final Collection<ArtifactCoordinate> coordinates, final ArtifactCoordinate expected) {
      return coordinates.stream()
          .anyMatch(value -> exactIdentity(value).equals(exactIdentity(expected)));
    }

    private Set<String> removedByPlan(
        final ArtifactCoordinate coordinate, final List<AnalyzePrediction.PlannedTrim> trims) {
      return trims.stream()
          .filter(value -> exactIdentity(value.coordinate()).equals(exactIdentity(coordinate)))
          .findFirst()
          .map(AnalyzePrediction.PlannedTrim::removedClasses)
          .orElse(Set.of());
    }

    private PrerequisitePrediction.MemberReason absenceReason(
        final List<PrerequisitePrediction.ProviderForecast> providers) {
      final long elided =
          providers.stream()
              .filter(value -> value.plan() == PrerequisitePrediction.ProviderPlan.ELIDED)
              .count();
      final long trimmed =
          providers.stream()
              .filter(value -> value.plan() == PrerequisitePrediction.ProviderPlan.TRIMMED_CLASS)
              .count();
      if (elided == providers.size()) {
        return PrerequisitePrediction.MemberReason.WOULD_ELIDE_DEPENDENCY;
      }
      if (trimmed == providers.size()) {
        return PrerequisitePrediction.MemberReason.WOULD_TRIM_CLASS;
      }
      return PrerequisitePrediction.MemberReason.MIXED;
    }
  }
}
