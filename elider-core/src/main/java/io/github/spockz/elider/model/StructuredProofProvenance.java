/* WHY: Retains the live CNA and source-build origin of structured omitted-code proof. */

package io.github.spockz.elider.model;

import java.util.List;
import java.util.Objects;

/** Audit provenance attached only to an ephemeral structured proof result. */
public record StructuredProofProvenance(
    String osvId,
    String cveSourceSha256,
    String cnaAffectedEntryIdentity,
    String affectedProductIdentity,
    OsvSourceAuthority osvSourceAuthority,
    ArtifactCoordinate sourcesCoordinate,
    String sourcesArchiveSha256,
    String sourceRepositoryProvenance,
    String compilerIdentity,
    List<String> compilerOptions,
    boolean conventionalLayoutAssumed,
    RawScopeEvidence rawScopeEvidence,
    List<ClaimAttribution> claimAttributions) {
  /** Freezes proof origin fields and checks their required identities. */
  public StructuredProofProvenance {
    requireText(osvId, "osvId");
    requireDigest(cveSourceSha256, "cveSourceSha256");
    requireText(cnaAffectedEntryIdentity, "cnaAffectedEntryIdentity");
    requireText(affectedProductIdentity, "affectedProductIdentity");
    Objects.requireNonNull(osvSourceAuthority, "osvSourceAuthority");
    Objects.requireNonNull(sourcesCoordinate, "sourcesCoordinate");
    requireDigest(sourcesArchiveSha256, "sourcesArchiveSha256");
    requireText(sourceRepositoryProvenance, "sourceRepositoryProvenance");
    requireText(compilerIdentity, "compilerIdentity");
    compilerOptions = List.copyOf(compilerOptions);
    Objects.requireNonNull(rawScopeEvidence, "rawScopeEvidence");
    claimAttributions = List.copyOf(claimAttributions);
    if (claimAttributions.isEmpty()) {
      throw new IllegalArgumentException("claimAttributions must not be empty");
    }
  }

  /** Records configured typed-index provenance without upstream authentication. */
  public enum OsvSourceAuthority {
    CONFIGURED_PRODUCER_COMPATIBLE_INDEX
  }

  /** Raw source version claims and evaluated statuses behind the AFFECTED decision. */
  public record RawScopeEvidence(
      String osvModified,
      String osvEcosystem,
      String osvPackageName,
      List<String> osvVersions,
      List<OsvAffectedRange> osvRanges,
      String cveState,
      String cnaDefaultStatus,
      List<CveVersionClaim> cnaVersions,
      String osvStatus,
      String cnaStatus,
      String osvRationale,
      String cnaRationale) {
    /** Freezes raw claim inputs and evaluation explanations. */
    public RawScopeEvidence {
      requireText(osvModified, "osvModified");
      requireText(osvEcosystem, "osvEcosystem");
      requireText(osvPackageName, "osvPackageName");
      osvVersions = List.copyOf(osvVersions);
      osvRanges = List.copyOf(osvRanges);
      requireText(cveState, "cveState");
      cnaVersions = List.copyOf(cnaVersions);
      requireText(osvStatus, "osvStatus");
      requireText(cnaStatus, "cnaStatus");
      requireText(osvRationale, "osvRationale");
      requireText(cnaRationale, "cnaRationale");
    }
  }

  /** One physical class-file entry and its SHA-256 digest. */
  public record ClassEntry(String path, String sha256) {
    /**
     * Creates a class entry.
     *
     * @param path physical jar path
     * @param sha256 entry digest
     */
    public ClassEntry {
      requireText(path, "path");
      requireDigest(sha256, "sha256");
    }
  }

  /** One live CNA claim and its reproduced source outputs. */
  public record ClaimAttribution(
      ClaimType type,
      String claim,
      String sourceEntry,
      String routineOwnerBinaryName,
      List<ClassEntry> emittedClasses) {
    /** Freezes class outputs and validates this source-to-class provenance edge. */
    public ClaimAttribution {
      Objects.requireNonNull(type, "type");
      requireText(claim, "claim");
      requireText(sourceEntry, "sourceEntry");
      if (type == ClaimType.ROUTINE) {
        requireText(routineOwnerBinaryName, "routineOwnerBinaryName");
      } else if (routineOwnerBinaryName != null) {
        throw new IllegalArgumentException("File claim cannot have a routine owner");
      }
      emittedClasses = List.copyOf(emittedClasses);
      if (emittedClasses.isEmpty()) {
        throw new IllegalArgumentException("emittedClasses must not be empty");
      }
    }
  }

  /** Distinguishes a CNA file claim from a uniquely resolved routine claim. */
  public enum ClaimType {
    FILE,
    ROUTINE
  }

  private static void requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must be nonblank");
    }
  }

  private static void requireDigest(final String value, final String field) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException(field + " must be a lowercase SHA-256");
    }
  }
}
