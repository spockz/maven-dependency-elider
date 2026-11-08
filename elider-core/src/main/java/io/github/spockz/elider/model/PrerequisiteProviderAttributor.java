/* WHY: Attributes prerequisite absence from observed provider changes without granting proof. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import io.github.spockz.elider.model.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.model.PreconditionProof.InventoryInspection;
import io.github.spockz.elider.model.PrerequisiteProofResult.GroupOutcome;
import io.github.spockz.elider.model.PrerequisiteProofResult.MemberOutcome;
import io.github.spockz.elider.model.PrerequisiteProofResult.ProviderOutcome;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

/** Maps exact class observations to baseline and final provider causes. */
// Attribution joins inspected providers with typed group observations.
@SuppressWarnings("PMD.CouplingBetweenObjects")
final class PrerequisiteProviderAttributor {
  /** Keeps provider observations stable for report consumers and tests. */
  private static final Comparator<ProviderOutcome> PROVIDER_ORDER =
      Comparator.comparing((ProviderOutcome value) -> value.kind().name())
          .thenComparing(
              value ->
                  value.coordinate() == null
                      ? ""
                      : PreconditionClassInventory.exactIdentity(value.coordinate()))
          .thenComparing(
              value -> value.baselinePath() == null ? "" : value.baselinePath().toString())
          .thenComparing(value -> value.finalPath() == null ? "" : value.finalPath().toString())
          .thenComparing(value -> value.attribution().name());

  private PrerequisiteProviderAttributor() {}

  /* package */ static PrerequisiteProofResult result(
      final VexAttestation attestation,
      final Set<PrerequisiteGroup> groups,
      final InventoryInspection baseline,
      final InventoryInspection actualFinal,
      final String baselineDetail) {
    final List<GroupOutcome> outcomes =
        new TreeSet<>(groups)
            .stream().map(group -> groupOutcome(group, baseline, actualFinal)).toList();
    return new PrerequisiteProofResult(attestation, outcomes, baselineDetail);
  }

  private static GroupOutcome groupOutcome(
      final PrerequisiteGroup group,
      final InventoryInspection baseline,
      final InventoryInspection actualFinal) {
    final List<MemberOutcome> members =
        group.members().stream()
            .sorted()
            .map(claim -> memberOutcome(claim, baseline, actualFinal))
            .toList();
    final Set<PrerequisiteAbsenceAttribution> disarmingCauses =
        new TreeSet<>(
            members.stream()
                .filter(
                    member ->
                        actualFinal.providersForClass(member.claim().requiresClass()).isEmpty())
                .map(MemberOutcome::attribution)
                .toList());
    return new GroupOutcome(group, combine(disarmingCauses), members);
  }

  private static MemberOutcome memberOutcome(
      final PrerequisiteClaim claim,
      final InventoryInspection baseline,
      final InventoryInspection actualFinal) {
    final List<Provider> finalProviders = actualFinal.providersForClass(claim.requiresClass());
    if (!finalProviders.isEmpty()) {
      return new MemberOutcome(
          claim,
          PrerequisiteAbsenceAttribution.PRESENT,
          providerObservations(claim, baseline, actualFinal, finalProviders));
    }
    if (baseline == null) {
      return new MemberOutcome(claim, PrerequisiteAbsenceAttribution.UNKNOWN, List.of());
    }
    final List<Provider> baselineProviders = baseline.providersForClass(claim.requiresClass());
    if (baselineProviders.isEmpty()) {
      return new MemberOutcome(claim, PrerequisiteAbsenceAttribution.ALREADY_ABSENT, List.of());
    }
    final List<ProviderOutcome> providers =
        baselineProviders.stream()
            .map(provider -> baselineOutcome(provider, claim, actualFinal))
            .toList();
    return new MemberOutcome(
        claim, combine(providers.stream().map(ProviderOutcome::attribution).toList()), providers);
  }

  private static List<ProviderOutcome> providerObservations(
      final PrerequisiteClaim claim,
      final InventoryInspection baseline,
      final InventoryInspection actualFinal,
      final List<Provider> finalClassProviders) {
    final List<Provider> baselineClassProviders =
        baseline == null ? List.of() : baseline.providersForClass(claim.requiresClass());
    final Stream<ProviderOutcome> previousProviders =
        baselineClassProviders.stream()
            .map(provider -> baselineOutcome(provider, claim, actualFinal));
    final Stream<ProviderOutcome> newProviders =
        finalClassProviders.stream()
            .filter(
                provider ->
                    baselineClassProviders.stream()
                        .noneMatch(previous -> sameIdentity(previous, provider)))
            .map(
                provider ->
                    new ProviderOutcome(
                        provider.kind(),
                        provider.coordinate(),
                        null,
                        provider.path(),
                        PrerequisiteAbsenceAttribution.PRESENT));
    return Stream.concat(previousProviders, newProviders).sorted(PROVIDER_ORDER).toList();
  }

  private static ProviderOutcome baselineOutcome(
      final Provider baseline,
      final PrerequisiteClaim claim,
      final InventoryInspection actualFinal) {
    final Provider finalProvider =
        actualFinal.providers().stream()
            .filter(provider -> sameIdentity(baseline, provider))
            .findFirst()
            .orElse(null);
    final PrerequisiteAbsenceAttribution attribution =
        providerAttribution(baseline, finalProvider, claim, actualFinal);
    final java.nio.file.Path finalPath = finalProvider == null ? null : finalProvider.path();
    return new ProviderOutcome(
        baseline.kind(), baseline.coordinate(), baseline.path(), finalPath, attribution);
  }

  private static PrerequisiteAbsenceAttribution providerAttribution(
      final Provider baseline,
      final Provider actualFinal,
      final PrerequisiteClaim claim,
      final InventoryInspection finalInspection) {
    if (baseline.kind() != ProviderKind.DEPENDENCY_ARCHIVE) {
      return hasClass(actualFinal, claim, finalInspection)
          ? PrerequisiteAbsenceAttribution.PRESENT
          : PrerequisiteAbsenceAttribution.UNKNOWN;
    }
    if (actualFinal == null) {
      return PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY;
    }
    return hasClass(actualFinal, claim, finalInspection)
        ? PrerequisiteAbsenceAttribution.PRESENT
        : PrerequisiteAbsenceAttribution.TRIMMED_CLASS;
  }

  private static boolean hasClass(
      final Provider provider,
      final PrerequisiteClaim claim,
      final InventoryInspection inspection) {
    return provider != null
        && inspection.providersForClass(claim.requiresClass()).contains(provider);
  }

  private static boolean sameIdentity(final Provider left, final Provider right) {
    if (left.kind() != right.kind()) {
      return false;
    }
    return left.kind() == ProviderKind.DEPENDENCY_ARCHIVE
        ? sameArtifact(left.coordinate(), right.coordinate())
        : left.path().equals(right.path());
  }

  private static boolean sameArtifact(
      final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return left.groupId().equals(right.groupId())
        && left.artifactId().equals(right.artifactId())
        && Objects.equals(left.version(), right.version())
        && left.type().equals(right.type())
        && left.classifier().equals(right.classifier());
  }

  private static PrerequisiteAbsenceAttribution combine(
      final Collection<PrerequisiteAbsenceAttribution> attributions) {
    final Set<PrerequisiteAbsenceAttribution> distinct = new TreeSet<>(attributions);
    if (distinct.isEmpty() || distinct.contains(PrerequisiteAbsenceAttribution.UNKNOWN)) {
      return PrerequisiteAbsenceAttribution.UNKNOWN;
    }
    return distinct.size() == 1 ? distinct.iterator().next() : PrerequisiteAbsenceAttribution.MIXED;
  }
}
