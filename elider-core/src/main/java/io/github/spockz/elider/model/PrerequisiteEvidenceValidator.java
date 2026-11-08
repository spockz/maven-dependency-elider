/* WHY: Keeps VEX evidence shape checks separate from the immutable attestation value. */

package io.github.spockz.elider.model;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Set;

/** Validates evidence before it enters the immutable attestation value. */
/* package */ final class PrerequisiteEvidenceValidator {
  /** Keeps construction within the attestation validation boundary. */
  private PrerequisiteEvidenceValidator() {}

  /* package */ static void validateOmittedCode(
      final Set<String> evidenceSymbols,
      final String originalSha256,
      final String trimmedSha256,
      final Set<PrerequisiteClaim> requiredPrerequisites,
      final Set<PrerequisiteGroup> groups,
      final Set<PrerequisiteMemberObservation> observations,
      final Path affectedArtifactPath,
      final String postElisionSha256,
      final String inventorySha256) {
    if (evidenceSymbols.isEmpty()) {
      throw new IllegalArgumentException("evidenceSymbols must not be empty");
    }
    requireSha256(originalSha256, "originalSha256");
    requireSha256(trimmedSha256, "trimmedSha256");
    if (hasPreconditionData(
        requiredPrerequisites,
        groups,
        observations,
        affectedArtifactPath,
        postElisionSha256,
        inventorySha256)) {
      throw new IllegalArgumentException(
          "Omitted-code evidence must not contain precondition data");
    }
  }

  /* package */ static Path validatePrecondition(
      final Set<String> evidenceSymbols,
      final String originalSha256,
      final String trimmedSha256,
      final Set<PrerequisiteClaim> requiredPrerequisites,
      final Set<PrerequisiteGroup> groups,
      final Set<PrerequisiteMemberObservation> observations,
      final Path affectedArtifactPath,
      final String postElisionSha256,
      final String inventorySha256) {
    if (!evidenceSymbols.isEmpty() || originalSha256 != null || trimmedSha256 != null) {
      throw new IllegalArgumentException(
          "Precondition evidence must not contain omitted-code symbols or digests");
    }
    if (requiredPrerequisites.isEmpty()) {
      throw new IllegalArgumentException("Precondition evidence requires a prerequisite set");
    }
    validatePrerequisiteObservations(requiredPrerequisites, groups, observations);
    final Path normalizedPath =
        canonicalizePath(Objects.requireNonNull(affectedArtifactPath, "affectedArtifactPath"));
    requireSha256(postElisionSha256, "postElisionSha256");
    requireSha256(inventorySha256, "inventorySha256");
    return normalizedPath;
  }

  /* package */ static void validatePrerequisiteObservations(
      final Set<PrerequisiteClaim> requiredPrerequisites,
      final Set<PrerequisiteGroup> groups,
      final Set<PrerequisiteMemberObservation> observations) {
    if (groups.isEmpty() || observations.isEmpty()) {
      throw new IllegalArgumentException(
          "Precondition evidence requires operator groups and member observations");
    }
    validateMemberSets(requiredPrerequisites, groups, observations);
    final java.util.Map<PrerequisiteClaim, PrerequisiteMemberObservation.State> states =
        observations.stream()
            .collect(
                java.util.stream.Collectors.toUnmodifiableMap(
                    PrerequisiteMemberObservation::claim, PrerequisiteMemberObservation::state));
    for (final PrerequisiteGroup group : groups) {
      if (!isDisarmed(group, states)) {
        throw new IllegalArgumentException(
            "Precondition member observations do not disarm every operator group");
      }
    }
  }

  private static boolean hasPreconditionData(
      final Set<PrerequisiteClaim> claims,
      final Set<PrerequisiteGroup> groups,
      final Set<PrerequisiteMemberObservation> observations,
      final Path path,
      final String postElisionSha256,
      final String inventorySha256) {
    return !claims.isEmpty()
        || !groups.isEmpty()
        || !observations.isEmpty()
        || path != null
        || postElisionSha256 != null
        || inventorySha256 != null;
  }

  private static void validateMemberSets(
      final Set<PrerequisiteClaim> requiredPrerequisites,
      final Set<PrerequisiteGroup> groups,
      final Set<PrerequisiteMemberObservation> observations) {
    final Set<PrerequisiteClaim> groupedClaims =
        groups.stream()
            .flatMap(group -> group.members().stream())
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    if (!requiredPrerequisites.equals(groupedClaims)) {
      throw new IllegalArgumentException(
          "Precondition groups must match the checked prerequisite members");
    }
    final Set<PrerequisiteClaim> observedClaims =
        observations.stream()
            .map(PrerequisiteMemberObservation::claim)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    if (!requiredPrerequisites.equals(observedClaims)) {
      throw new IllegalArgumentException(
          "Precondition member observations must match checked prerequisite members");
    }
  }

  private static boolean isDisarmed(
      final PrerequisiteGroup group,
      final java.util.Map<PrerequisiteClaim, PrerequisiteMemberObservation.State> states) {
    final long absentCount =
        group.members().stream()
            .filter(claim -> states.get(claim) == PrerequisiteMemberObservation.State.ABSENT)
            .count();
    return switch (group.operator()) {
      case ANY_OF -> absentCount == group.members().size();
      case ALL_OF -> absentCount > 0;
    };
  }

  private static void requireSha256(final String value, final String name) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException(name + " must be a lowercase SHA-256 digest");
    }
  }

  private static Path canonicalizePath(final Path path) {
    try {
      if (Files.exists(path)) {
        return path.toRealPath();
      }
    } catch (final IOException ignored) {
      // Fall through to toAbsolutePath().normalize()
    }
    return path.toAbsolutePath().normalize();
  }
}
