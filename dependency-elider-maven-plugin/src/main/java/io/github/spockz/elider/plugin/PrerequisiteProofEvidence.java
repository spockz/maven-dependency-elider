/* WHY: Preserves inspected prerequisite outcomes for offline report replay
 * without proof authority. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.applicability.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.applicability.PrerequisiteProofResult;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.HexDigest;
import io.github.spockz.elider.model.PrerequisiteAbsenceAttribution;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteMemberObservation;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Detached, non-authoritative copy of prerequisite proof observations. */
record PrerequisiteProofEvidence(
    ArtifactCoordinate candidate,
    String finalInventoryFingerprint,
    Path affectedArtifactPath,
    String postElisionSha256,
    List<GroupEvidence> groups,
    String baselineDetail) {
  /** Names the group array in validation diagnostics. */
  private static final String GROUPS_FIELD = "groups";

  /** Freezes proof groups and validates the binding fields. */
  PrerequisiteProofEvidence {
    Objects.requireNonNull(candidate, "candidate");
    requireDigest(finalInventoryFingerprint, "finalInventoryFingerprint");
    affectedArtifactPath =
        Objects.requireNonNull(affectedArtifactPath, "affectedArtifactPath")
            .toAbsolutePath()
            .normalize();
    requireDigest(postElisionSha256, "postElisionSha256");
    groups = List.copyOf(Objects.requireNonNull(groups, GROUPS_FIELD));
    if (groups.isEmpty()) {
      throw new IllegalArgumentException("Prerequisite proof evidence requires groups");
    }
    if (baselineDetail != null && baselineDetail.isBlank()) {
      throw new IllegalArgumentException("baselineDetail must be absent or nonblank");
    }
    validateGroups(groups, baselineDetail);
  }

  /* package */ static PrerequisiteProofEvidence from(final PrerequisiteProofResult proof) {
    Objects.requireNonNull(proof, "proof");
    final List<GroupEvidence> groups =
        proof.groups().stream()
            .map(
                group ->
                    new GroupEvidence(
                        group.group(),
                        group.attribution(),
                        group.members().stream()
                            .map(
                                member ->
                                    new MemberEvidence(
                                        member.claim(),
                                        observationState(member.attribution()),
                                        member.attribution(),
                                        member.providers().stream()
                                            .map(ProviderEvidence::from)
                                            .toList()))
                            .toList()))
            .toList();
    return new PrerequisiteProofEvidence(
        proof.attestation().coordinate(),
        proof.attestation().inventorySha256(),
        proof.attestation().affectedArtifactPath(),
        proof.attestation().postElisionSha256(),
        groups,
        proof.baselineDetail());
  }

  private static PrerequisiteMemberObservation.State observationState(
      final PrerequisiteAbsenceAttribution attribution) {
    return attribution == PrerequisiteAbsenceAttribution.PRESENT
        ? PrerequisiteMemberObservation.State.PRESENT
        : PrerequisiteMemberObservation.State.ABSENT;
  }

  // This map is local to validation; only this constructor thread writes it.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static void validateGroups(
      final List<GroupEvidence> groups, final String baselineDetail) {
    final Set<PrerequisiteGroup> uniqueGroups = new TreeSet<>();
    final Map<PrerequisiteClaim, MemberEvidence> observations = new HashMap<>();
    for (int groupIndex = 0; groupIndex < groups.size(); groupIndex++) {
      final GroupEvidence evidence = groups.get(groupIndex);
      if (!uniqueGroups.add(evidence.group())) {
        throw new IllegalArgumentException(groupPath(groupIndex) + " is a duplicate group");
      }
      validateGroup(evidence, groupIndex, baselineDetail, observations);
    }
  }

  private static void validateGroup(
      final GroupEvidence evidence,
      final int groupIndex,
      final String baselineDetail,
      final Map<PrerequisiteClaim, MemberEvidence> observations) {
    if (!evidence.group().members().equals(memberClaims(evidence))) {
      throw new IllegalArgumentException(
          groupPath(groupIndex) + " members do not match their group");
    }
    final List<MemberEvidence> absentMembers =
        evidence.members().stream()
            .filter(member -> member.state() == PrerequisiteMemberObservation.State.ABSENT)
            .toList();
    validateGroupMembers(evidence, groupIndex, baselineDetail, absentMembers, observations);
    if (!isDisarmed(evidence, absentMembers)) {
      throw new IllegalArgumentException(
          groupPath(groupIndex) + " member observations do not disarm the group");
    }
    final PrerequisiteAbsenceAttribution expectedAttribution =
        combine(absentMembers.stream().map(MemberEvidence::attribution).toList());
    if (evidence.attribution() != expectedAttribution) {
      throw new IllegalArgumentException(
          groupPath(groupIndex) + ".attribution conflicts with absent member causes");
    }
  }

  private static Set<PrerequisiteClaim> memberClaims(final GroupEvidence evidence) {
    return evidence.members().stream()
        .map(MemberEvidence::claim)
        .collect(java.util.stream.Collectors.toSet());
  }

  private static void validateGroupMembers(
      final GroupEvidence evidence,
      final int groupIndex,
      final String baselineDetail,
      final List<MemberEvidence> absentMembers,
      final Map<PrerequisiteClaim, MemberEvidence> observations) {
    for (int memberIndex = 0; memberIndex < evidence.members().size(); memberIndex++) {
      final MemberEvidence member = evidence.members().get(memberIndex);
      final MemberEvidence prior = observations.putIfAbsent(member.claim(), member);
      if (prior != null && !prior.equals(member)) {
        throw new IllegalArgumentException(
            groupPath(groupIndex)
                + ".members["
                + memberIndex
                + "] conflicts with a repeated"
                + " prerequisite claim");
      }
      if (absentMembers.contains(member)) {
        validateAbsentMember(member, groupIndex, memberIndex, baselineDetail);
      }
    }
  }

  private static void validateAbsentMember(
      final MemberEvidence member,
      final int groupIndex,
      final int memberIndex,
      final String baselineDetail) {
    final String memberPath = groupPath(groupIndex) + ".members[" + memberIndex + "]";
    if (baselineDetail != null && !member.providers().isEmpty()) {
      throw new IllegalArgumentException(
          memberPath
              + ".attribution cannot use provider transitions when baseline inspection"
              + " failed");
    }
    if (member.providers().isEmpty()) {
      final PrerequisiteAbsenceAttribution expected =
          baselineDetail == null
              ? PrerequisiteAbsenceAttribution.ALREADY_ABSENT
              : PrerequisiteAbsenceAttribution.UNKNOWN;
      if (member.attribution() != expected) {
        throw new IllegalArgumentException(
            memberPath + ".attribution conflicts with baseline detail");
      }
    }
  }

  private static boolean isDisarmed(
      final GroupEvidence evidence, final List<MemberEvidence> absentMembers) {
    return switch (evidence.group().operator()) {
      case ANY_OF -> absentMembers.size() == evidence.members().size();
      case ALL_OF -> !absentMembers.isEmpty();
    };
  }

  private static String groupPath(final int groupIndex) {
    return GROUPS_FIELD + "[" + groupIndex + "]";
  }

  private static PrerequisiteAbsenceAttribution combine(
      final List<PrerequisiteAbsenceAttribution> causes) {
    if (causes.isEmpty() || causes.contains(PrerequisiteAbsenceAttribution.UNKNOWN)) {
      return PrerequisiteAbsenceAttribution.UNKNOWN;
    }
    final Set<PrerequisiteAbsenceAttribution> distinct = new TreeSet<>(causes);
    return distinct.size() == 1 ? distinct.iterator().next() : PrerequisiteAbsenceAttribution.MIXED;
  }

  private static void requireDigest(final String value, final String field) {
    HexDigest.requireSha256(value, field);
  }

  /** One operator group and its observed members. */
  /* package */ record GroupEvidence(
      PrerequisiteGroup group,
      PrerequisiteAbsenceAttribution attribution,
      List<MemberEvidence> members) {
    /** Freezes member outcomes. */
    GroupEvidence {
      Objects.requireNonNull(group, "group");
      Objects.requireNonNull(attribution, "attribution");
      members = List.copyOf(Objects.requireNonNull(members, "members"));
      if (members.isEmpty()) {
        throw new IllegalArgumentException("Prerequisite group evidence requires members");
      }
    }
  }

  /** One checked pair, its final state, and the baseline/final attribution. */
  /* package */ record MemberEvidence(
      PrerequisiteClaim claim,
      PrerequisiteMemberObservation.State state,
      PrerequisiteAbsenceAttribution attribution,
      List<ProviderEvidence> providers) {
    /** Freezes providers and checks state/cause agreement. */
    MemberEvidence {
      Objects.requireNonNull(claim, "claim");
      Objects.requireNonNull(state, "state");
      Objects.requireNonNull(attribution, "attribution");
      providers = List.copyOf(Objects.requireNonNull(providers, "providers"));
      validateUniqueProviders(providers);
      if ((state == PrerequisiteMemberObservation.State.PRESENT)
          != (attribution == PrerequisiteAbsenceAttribution.PRESENT)) {
        throw new IllegalArgumentException("Prerequisite member state conflicts with attribution");
      }
      if (state == PrerequisiteMemberObservation.State.PRESENT
          && providers.stream()
              .noneMatch(
                  provider ->
                      provider.attribution() == PrerequisiteAbsenceAttribution.PRESENT
                          && provider.finalPath() != null)) {
        throw new IllegalArgumentException("Present prerequisite member requires a final provider");
      }
      if (state == PrerequisiteMemberObservation.State.ABSENT
          && providers.stream()
              .anyMatch(
                  provider -> provider.attribution() == PrerequisiteAbsenceAttribution.PRESENT)) {
        throw new IllegalArgumentException(
            "Absent prerequisite member cannot have a final class-present provider");
      }
      final PrerequisiteAbsenceAttribution expectedAttribution =
          providers.isEmpty()
              ? attribution == PrerequisiteAbsenceAttribution.ALREADY_ABSENT
                      || attribution == PrerequisiteAbsenceAttribution.UNKNOWN
                  ? attribution
                  : null
              : combine(providers.stream().map(ProviderEvidence::attribution).toList());
      if (state == PrerequisiteMemberObservation.State.ABSENT
          && attribution != expectedAttribution) {
        throw new IllegalArgumentException("Member attribution conflicts with its provider causes");
      }
    }

    private static void validateUniqueProviders(final List<ProviderEvidence> providers) {
      final Set<Path> paths = new HashSet<>();
      final Set<String> dependencyIdentities = new HashSet<>();
      for (final ProviderEvidence provider : providers) {
        final Path path =
            provider.baselinePath() == null ? provider.finalPath() : provider.baselinePath();
        if (!paths.add(path)) {
          throw new IllegalArgumentException("duplicate provider path: " + path);
        }
        if (provider.kind() == ProviderKind.DEPENDENCY_ARCHIVE
            && !dependencyIdentities.add(provider.coordinate().toId())) {
          throw new IllegalArgumentException(
              "duplicate dependency provider identity: " + provider.coordinate().toId());
        }
      }
    }
  }

  /** One provider’s exact artifact/path/digest observations and cause. */
  /* package */ record ProviderEvidence(
      ProviderKind kind,
      ArtifactCoordinate coordinate,
      Path baselinePath,
      String baselineSha256,
      Path finalPath,
      String finalSha256,
      PrerequisiteAbsenceAttribution attribution) {
    /** Validates exact provider identity and the paired path/digest fields. */
    ProviderEvidence {
      Objects.requireNonNull(kind, "kind");
      if (kind == ProviderKind.DEPENDENCY_ARCHIVE) {
        if (coordinate == null) {
          throw new IllegalArgumentException("dependency provider requires a coordinate");
        }
      } else if (coordinate != null) {
        throw new IllegalArgumentException(
            "providers using application classes have no coordinate");
      }
      baselinePath = normalizedPath(baselinePath);
      finalPath = normalizedPath(finalPath);
      validateProviderDigest(baselinePath, baselineSha256, "baseline");
      validateProviderDigest(finalPath, finalSha256, "final");
      if (kind != ProviderKind.DEPENDENCY_ARCHIVE
          && baselinePath != null
          && finalPath != null
          && !baselinePath.equals(finalPath)) {
        throw new IllegalArgumentException(
            "Application provider must retain the same path across snapshots");
      }
      if (baselinePath == null && finalPath == null) {
        throw new IllegalArgumentException("Provider evidence requires a baseline or final path");
      }
      Objects.requireNonNull(attribution, "attribution");
      validateProviderTransition(
          kind, attribution, baselinePath, baselineSha256, finalPath, finalSha256);
    }

    // Checkstyle requires a default arm on this exhaustive enum switch.
    @SuppressWarnings("PMD.ExhaustiveSwitchHasDefault")
    private static void validateProviderTransition(
        final ProviderKind kind,
        final PrerequisiteAbsenceAttribution attribution,
        final Path baselinePath,
        final String baselineSha256,
        final Path finalPath,
        final String finalSha256) {
      switch (attribution) {
        case PRESENT -> requireFinalPath(finalPath);
        case ELIDED_DEPENDENCY -> validateElided(kind, baselinePath, finalPath);
        case TRIMMED_CLASS ->
            validateTrimmed(kind, baselinePath, baselineSha256, finalPath, finalSha256);
        case ALREADY_ABSENT, MIXED ->
            throw new IllegalArgumentException(
                attribution + " is an aggregate outcome, not a provider transition");
        case UNKNOWN -> validateUnknown(kind, baselinePath, baselineSha256, finalPath, finalSha256);
        default ->
            throw new IllegalArgumentException("Unsupported provider attribution: " + attribution);
      }
    }

    private static void requireFinalPath(final Path finalPath) {
      if (finalPath == null) {
        throw new IllegalArgumentException("PRESENT provider requires a final path");
      }
    }

    private static void validateElided(
        final ProviderKind kind, final Path baselinePath, final Path finalPath) {
      if (kind != ProviderKind.DEPENDENCY_ARCHIVE || baselinePath == null || finalPath != null) {
        throw new IllegalArgumentException(
            "ELIDED_DEPENDENCY provider requires only a baseline dependency path");
      }
    }

    private static void validateTrimmed(
        final ProviderKind kind,
        final Path baselinePath,
        final String baselineSha256,
        final Path finalPath,
        final String finalSha256) {
      if (kind != ProviderKind.DEPENDENCY_ARCHIVE || baselinePath == null || finalPath == null) {
        throw new IllegalArgumentException(
            "TRIMMED_CLASS provider requires baseline and final dependency paths");
      }
      if (baselineSha256.equals(finalSha256)) {
        throw new IllegalArgumentException("TRIMMED_CLASS provider requires changed archive bytes");
      }
    }

    private static void validateUnknown(
        final ProviderKind kind,
        final Path baselinePath,
        final String baselineSha256,
        final Path finalPath,
        final String finalSha256) {
      if (kind == ProviderKind.DEPENDENCY_ARCHIVE || baselinePath == null) {
        throw new IllegalArgumentException(
            "UNKNOWN provider requires a baseline application provider path");
      }
      if (finalPath != null && baselineSha256.equals(finalSha256)) {
        throw new IllegalArgumentException(
            "UNKNOWN application provider requires changed or unavailable snapshot bytes");
      }
    }

    private static Path normalizedPath(final Path path) {
      return path == null ? null : path.toAbsolutePath().normalize();
    }

    private static void validateProviderDigest(
        final Path path, final String digest, final String stage) {
      if (path == null && digest != null) {
        throw new IllegalArgumentException(stage + " digest requires its provider path");
      }
      if (path != null) {
        requireDigest(digest, stage + " provider SHA-256");
      }
    }

    private static ProviderEvidence from(final PrerequisiteProofResult.ProviderOutcome outcome) {
      return new ProviderEvidence(
          outcome.kind(),
          outcome.coordinate(),
          outcome.baselinePath(),
          outcome.baselineSha256(),
          outcome.finalPath(),
          outcome.finalSha256(),
          outcome.attribution());
    }
  }
}
