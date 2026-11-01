// WHY: Carries reproducible source-to-archive correspondence without creating proof authority.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.correspondence.SourceReproductionResult;
import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Immutable result of a single exact source/build correspondence attempt. */
@SuppressWarnings("PMD.PublicMemberInNonPublicType") // Interface records are implicitly public.
sealed interface SourceBuildCorrespondence {
  /** Returns the exact assessed component associated with this review result. */
  ArtifactCoordinate candidate();

  /** Returns the CVE alias bound to the retained source claim. */
  String cveId();

  /** Returns the digest binding this result to the source record bytes. */
  String sourceRecordSha256();

  /** Returns the source entry locator that selected the structured claim. */
  String cnaAffectedEntryIdentity();

  record Matched(
      ArtifactCoordinate candidate,
      String osvId,
      String cveId,
      String sourceRecordSha256,
      String cnaAffectedEntryIdentity,
      String sourcesCoordinate,
      String sourceRepositoryProvenance,
      String originalArchiveSha256,
      String sourcesArchiveSha256,
      String compilerIdentity,
      List<String> compilerOptions,
      Map<String, String> mappedProgramFiles,
      List<SourceReproductionResult.ClassEntry> originalClassInventory,
      List<SourceReproductionResult.SourceUnit> sourceUnits)
      implements SourceBuildCorrespondence {
    public Matched {
      requireOwnerIdentity(candidate, osvId, cveId);
      requireSourceIdentity(sourceRecordSha256, cnaAffectedEntryIdentity);
      requireDigest(originalArchiveSha256, "originalArchiveSha256");
      requireDigest(sourcesArchiveSha256, "sourcesArchiveSha256");
      if (sourcesCoordinate == null || sourcesCoordinate.isBlank()) {
        throw new IllegalArgumentException("sourcesCoordinate must be nonblank");
      }
      if (sourceRepositoryProvenance == null || sourceRepositoryProvenance.isBlank()) {
        throw new IllegalArgumentException("sourceRepositoryProvenance must be nonblank");
      }
      if (compilerIdentity == null || compilerIdentity.isBlank()) {
        throw new IllegalArgumentException("compilerIdentity must be nonblank");
      }
      compilerOptions = List.copyOf(compilerOptions);
      mappedProgramFiles = Collections.unmodifiableMap(new TreeMap<>(mappedProgramFiles));
      originalClassInventory = List.copyOf(originalClassInventory);
      sourceUnits = List.copyOf(sourceUnits);
    }
  }

  record Abstained(
      ArtifactCoordinate candidate,
      String osvId,
      String cveId,
      String sourceRecordSha256,
      String cnaAffectedEntryIdentity,
      String rationale)
      implements SourceBuildCorrespondence {
    public Abstained {
      requireOwnerIdentity(candidate, osvId, cveId);
      requireSourceIdentity(sourceRecordSha256, cnaAffectedEntryIdentity);
      if (rationale == null || rationale.isBlank()) {
        throw new IllegalArgumentException("rationale must be nonblank");
      }
    }
  }

  /** Validates owner identity shared by matched and abstained outcomes. */
  /* default */ static void requireOwnerIdentity(
      final ArtifactCoordinate candidate, final String osvId, final String cveId) {
    if (candidate == null || osvId == null || osvId.isBlank() || cveId == null || cveId.isBlank()) {
      throw new IllegalArgumentException("Correspondence owner identity is required");
    }
  }

  /** Validates source provenance shared by matched and abstained outcomes. */
  /* default */ static void requireSourceIdentity(
      final String sourceRecordSha256, final String cnaAffectedEntryIdentity) {
    requireDigest(sourceRecordSha256, "sourceRecordSha256");
    if (cnaAffectedEntryIdentity == null || cnaAffectedEntryIdentity.isBlank()) {
      throw new IllegalArgumentException("cnaAffectedEntryIdentity must be nonblank");
    }
  }

  private static void requireDigest(final String value, final String name) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException(name + " must be a lowercase SHA-256");
    }
  }
}
