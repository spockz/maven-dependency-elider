/* WHY: Carries physical proof with the provider observations that explain its attribution. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.model.PreconditionClassInventory.ProviderKind;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/** Immutable proof with provider-level absence causes. */
public record PrerequisiteProofResult(
    VexAttestation attestation, List<GroupOutcome> groups, String baselineDetail) {
  /** Freezes ordered observations and requires an actual-final attestation. */
  public PrerequisiteProofResult {
    Objects.requireNonNull(attestation, "attestation");
    groups = List.copyOf(Objects.requireNonNull(groups, "groups"));
    if (groups.isEmpty()) {
      throw new IllegalArgumentException("Prerequisite proof result requires group observations");
    }
  }

  /** Outcome for one selected atomic prerequisite group. */
  public record GroupOutcome(
      PrerequisiteGroup group,
      PrerequisiteAbsenceAttribution attribution,
      List<MemberOutcome> members) {
    /** Freezes member observations for this atomic group. */
    public GroupOutcome {
      Objects.requireNonNull(group, "group");
      Objects.requireNonNull(attribution, "attribution");
      members = List.copyOf(Objects.requireNonNull(members, "members"));
      if (members.isEmpty()) {
        throw new IllegalArgumentException("Group outcome requires member observations");
      }
    }
  }

  /** Outcome for one exact dependency and class pair. */
  public record MemberOutcome(
      PrerequisiteClaim claim,
      PrerequisiteAbsenceAttribution attribution,
      List<ProviderOutcome> providers) {
    /** Freezes all observed providers for this exact class. */
    public MemberOutcome {
      Objects.requireNonNull(claim, "claim");
      Objects.requireNonNull(attribution, "attribution");
      providers = List.copyOf(Objects.requireNonNull(providers, "providers"));
    }
  }

  /** One baseline/final provider identity and its observed class outcome. */
  public record ProviderOutcome(
      ProviderKind kind,
      ArtifactCoordinate coordinate,
      Path baselinePath,
      String baselineSha256,
      Path finalPath,
      String finalSha256,
      PrerequisiteAbsenceAttribution attribution) {
    /** Validates the identity and cause of this provider observation. */
    public ProviderOutcome {
      Objects.requireNonNull(kind, "kind");
      if (kind == ProviderKind.DEPENDENCY_ARCHIVE) {
        Objects.requireNonNull(coordinate, "dependency provider coordinate");
      } else if (coordinate != null) {
        throw new IllegalArgumentException("Application provider must not have a coordinate");
      }
      if (baselinePath == null && finalPath == null) {
        throw new IllegalArgumentException("Provider outcome requires a baseline or final path");
      }
      validateDigestForPath(baselinePath, baselineSha256, "baseline");
      validateDigestForPath(finalPath, finalSha256, "final");
      Objects.requireNonNull(attribution, "attribution");
    }

    private static void validateDigestForPath(
        final Path path, final String digest, final String stage) {
      if (path == null && digest != null) {
        throw new IllegalArgumentException(stage + " digest requires a provider path");
      }
      if (path != null && (digest == null || !digest.matches("[0-9a-f]{64}"))) {
        throw new IllegalArgumentException(stage + " provider requires a lowercase SHA-256 digest");
      }
    }
  }
}
