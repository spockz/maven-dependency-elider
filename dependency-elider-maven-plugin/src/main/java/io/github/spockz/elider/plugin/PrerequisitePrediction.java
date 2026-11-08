/* WHY: Records Analyze's planned prerequisite membership without physical proof authority. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteOperator;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/** Immutable, report-safe forecast of selected prerequisite groups. */
record PrerequisitePrediction(
    ArtifactCoordinate candidate,
    String baselineInventoryFingerprint,
    String planFingerprint,
    List<GroupForecast> groups,
    String detail) {
  PrerequisitePrediction {
    Objects.requireNonNull(candidate, "candidate");
    requireDigest(baselineInventoryFingerprint, "baselineInventoryFingerprint");
    requireDigest(planFingerprint, "planFingerprint");
    groups = List.copyOf(Objects.requireNonNull(groups, "groups"));
    if (groups.isEmpty()) {
      throw new IllegalArgumentException("Prerequisite prediction requires selected groups");
    }
    if (groups.stream().map(GroupForecast::group).distinct().count() != groups.size()) {
      throw new IllegalArgumentException("Prediction groups must be distinct");
    }
    final boolean conflictingMemberForecast =
        groups.stream()
            .flatMap(group -> group.members().stream())
            .collect(
                java.util.stream.Collectors.groupingBy(
                    MemberForecast::claim, java.util.stream.Collectors.toSet()))
            .values()
            .stream()
            .anyMatch(forecasts -> forecasts.size() > 1);
    if (conflictingMemberForecast) {
      throw new IllegalArgumentException("A repeated member claim has conflicting forecast");
    }
    final boolean hasUnknown =
        groups.stream()
            .flatMap(group -> group.members().stream())
            .anyMatch(member -> member.state() == MemberState.UNKNOWN);
    if (hasUnknown && detail == null) {
      throw new IllegalArgumentException("Unknown member state requires inventory detail");
    }
    if (detail != null
        && groups.stream()
            .flatMap(group -> group.members().stream())
            .anyMatch(member -> member.state() == MemberState.ABSENT)) {
      throw new IllegalArgumentException("Incomplete inventory cannot predict class absence");
    }
  }

  /** Whether each exact prerequisite class survives the Analyze plan. */
  /* package */ enum MemberState {
    PRESENT,
    ABSENT,
    UNKNOWN
  }

  /** The planned provider transition or unresolved baseline cause. */
  /* package */ enum MemberReason {
    PRESENT,
    ALREADY_ABSENT,
    WOULD_ELIDE_DEPENDENCY,
    WOULD_TRIM_CLASS,
    MIXED,
    UNKNOWN
  }

  /** How Analyze plans to treat one baseline provider. */
  /* package */ enum ProviderPlan {
    RETAINED,
    ELIDED,
    TRIMMED_CLASS
  }

  /** One selected prerequisite group with its independently checked members. */
  /* package */ record GroupForecast(
      PrerequisiteGroup group, List<MemberForecast> members, boolean disarmed) {
    GroupForecast {
      Objects.requireNonNull(group, "group");
      members = List.copyOf(Objects.requireNonNull(members, "members"));
      if (!members.stream()
              .map(MemberForecast::claim)
              .collect(java.util.stream.Collectors.toSet())
              .equals(group.members())
          || members.stream().map(MemberForecast::claim).distinct().count() != members.size()) {
        throw new IllegalArgumentException("Prediction members do not match selected group");
      }
      final boolean expectedDisarmed =
          group.operator() == PrerequisiteOperator.ANY_OF
              ? members.stream().allMatch(member -> member.state() == MemberState.ABSENT)
              : members.stream().anyMatch(member -> member.state() == MemberState.ABSENT);
      if (disarmed != expectedDisarmed) {
        throw new IllegalArgumentException("Prediction group disarmed state is inconsistent");
      }
    }
  }

  /** One class membership observation and the baseline providers that explain it. */
  /* package */ record MemberForecast(
      PrerequisiteClaim claim,
      MemberState state,
      MemberReason reason,
      List<ProviderForecast> providers,
      String detail) {
    MemberForecast {
      Objects.requireNonNull(claim, "claim");
      Objects.requireNonNull(state, "state");
      Objects.requireNonNull(reason, "reason");
      providers = List.copyOf(Objects.requireNonNull(providers, "providers"));
      if (providers.stream().map(ProviderForecast::baselinePath).distinct().count()
          != providers.size()) {
        throw new IllegalArgumentException("Prediction provider paths must be distinct");
      }
      if (providers.stream()
              .filter(value -> value.kind() == ProviderKind.DEPENDENCY_ARCHIVE)
              .map(value -> value.coordinate().toId())
              .distinct()
              .count()
          != providers.stream()
              .filter(value -> value.kind() == ProviderKind.DEPENDENCY_ARCHIVE)
              .count()) {
        throw new IllegalArgumentException("Prediction dependency identities must be distinct");
      }
      if (detail != null && detail.isBlank()) {
        throw new IllegalArgumentException("member detail must be absent or nonblank");
      }
      validateOutcome(state, reason, providers);
      if ((state == MemberState.UNKNOWN) != (detail != null)) {
        throw new IllegalArgumentException("Unknown member state requires a concrete detail");
      }
      if ((state == MemberState.PRESENT) != (reason == MemberReason.PRESENT)
          || (state == MemberState.UNKNOWN) != (reason == MemberReason.UNKNOWN)) {
        throw new IllegalArgumentException("Prediction member reason disagrees with its state");
      }
      validateAbsentMember(state, reason, providers);
    }
  }

  @SuppressWarnings("PMD.ExhaustiveSwitchHasDefault")
  private static void validateOutcome(
      final MemberState state, final MemberReason reason, final List<ProviderForecast> providers) {
    switch (state) {
      case PRESENT -> validatePresent(providers);
      case ABSENT -> validateAbsent(reason, providers);
      case UNKNOWN -> validateUnknown(providers);
      default -> throw new IllegalStateException("Unhandled prediction member state: " + state);
    }
  }

  private static void validatePresent(final List<ProviderForecast> providers) {
    if (providers.isEmpty() || providers.stream().noneMatch(ProviderForecast::survives)) {
      throw new IllegalArgumentException("A present member requires a surviving provider");
    }
  }

  private static void validateAbsent(
      final MemberReason reason, final List<ProviderForecast> providers) {
    if (providers.stream().anyMatch(ProviderForecast::survives)) {
      throw new IllegalArgumentException("An absent member cannot have a surviving provider");
    }
    validateAbsentReason(reason, providers);
  }

  private static void validateUnknown(final List<ProviderForecast> providers) {
    if (providers.stream().anyMatch(ProviderForecast::survives)) {
      throw new IllegalArgumentException("A known surviving provider makes the member present");
    }
  }

  private static void validateAbsentMember(
      final MemberState state, final MemberReason reason, final List<ProviderForecast> providers) {
    if (reason == MemberReason.ALREADY_ABSENT && !providers.isEmpty()) {
      throw new IllegalArgumentException("Already-absent class cannot have baseline providers");
    }
    if (state == MemberState.ABSENT && providers.stream().anyMatch(ProviderForecast::survives)) {
      throw new IllegalArgumentException("An absent member cannot have a surviving provider");
    }
  }

  private static void validateAbsentReason(
      final MemberReason reason, final List<ProviderForecast> providers) {
    if (providers.isEmpty()) {
      if (reason != MemberReason.ALREADY_ABSENT) {
        throw new IllegalArgumentException("An ownerless absent member is already absent");
      }
      return;
    }
    final long elided =
        providers.stream().filter(value -> value.plan() == ProviderPlan.ELIDED).count();
    final long trimmed =
        providers.stream().filter(value -> value.plan() == ProviderPlan.TRIMMED_CLASS).count();
    final MemberReason expected =
        elided == providers.size()
            ? MemberReason.WOULD_ELIDE_DEPENDENCY
            : trimmed == providers.size() ? MemberReason.WOULD_TRIM_CLASS : MemberReason.MIXED;
    if (reason != expected) {
      throw new IllegalArgumentException("Absent member reason disagrees with provider plans");
    }
  }

  /** One baseline provider and its planned disposition. */
  /* package */ record ProviderForecast(
      ProviderKind kind,
      ArtifactCoordinate coordinate,
      Path baselinePath,
      String baselineSha256,
      ProviderPlan plan) {
    ProviderForecast {
      Objects.requireNonNull(kind, "kind");
      baselinePath =
          Objects.requireNonNull(baselinePath, "baselinePath").toAbsolutePath().normalize();
      requireDigest(baselineSha256, "baselineSha256");
      Objects.requireNonNull(plan, "plan");
      if ((kind == ProviderKind.DEPENDENCY_ARCHIVE) != (coordinate != null)) {
        throw new IllegalArgumentException("Prediction provider coordinate disagrees with kind");
      }
      if (kind != ProviderKind.DEPENDENCY_ARCHIVE && plan != ProviderPlan.RETAINED) {
        throw new IllegalArgumentException("Application providers cannot be planned for removal");
      }
    }

    /* package */ boolean survives() {
      return plan == ProviderPlan.RETAINED;
    }
  }

  private static void requireDigest(final String value, final String field) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException(field + " must be a lowercase SHA-256 value");
    }
  }
}
