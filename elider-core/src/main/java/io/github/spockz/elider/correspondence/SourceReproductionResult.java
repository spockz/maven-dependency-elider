// WHY: Returns byte-reproduction observations without granting proof
// or classification authority.

package io.github.spockz.elider.correspondence;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Result of one source reproduction attempt. */
public sealed interface SourceReproductionResult
    permits SourceReproductionResult.Completed, SourceReproductionResult.Abstained {
  /** Physical class entry and its bytes' digest. */
  record ClassEntry(String path, String sha256) {
    public ClassEntry {
      if (path == null || path.isBlank() || !SourceFileDigest.isCanonicalSha256(sha256)) {
        throw new IllegalArgumentException("Invalid reproduction class entry");
      }
    }
  }

  /** Resolved routine owner observed while analyzing one source unit. */
  record RoutineDeclaration(String name, String ownerBinaryName) {
    public RoutineDeclaration {
      if (name == null || name.isBlank() || ownerBinaryName == null || ownerBinaryName.isBlank()) {
        throw new IllegalArgumentException("Routine declaration identity is required");
      }
    }
  }

  /** One explicit source-unit compilation and its complete emitted class family. */
  record SourceUnit(
      String sourceEntry,
      String sourceSha256,
      Set<String> topLevelTypes,
      List<RoutineDeclaration> routineDeclarations,
      List<ClassEntry> emittedClasses) {
    public SourceUnit {
      if (sourceEntry == null || sourceEntry.isBlank()) {
        throw new IllegalArgumentException("sourceEntry must be nonblank");
      }
      if (!SourceFileDigest.isCanonicalSha256(sourceSha256)) {
        throw new IllegalArgumentException("sourceSha256 must be a lowercase SHA-256");
      }
      topLevelTypes = Collections.unmodifiableSet(new TreeSet<>(topLevelTypes));
      routineDeclarations = List.copyOf(routineDeclarations);
      emittedClasses = List.copyOf(emittedClasses);
    }
  }

  /** Complete byte-equal reproduction; this is still only correspondence evidence. */
  record Completed(
      ArtifactCoordinate candidate,
      ArtifactCoordinate sourcesCoordinate,
      String sourceRepositoryProvenance,
      String originalArchiveSha256,
      String sourcesArchiveSha256,
      String compilerIdentity,
      List<String> compilerOptions,
      List<ClassEntry> originalClassInventory,
      List<SourceUnit> sourceUnits,
      Map<String, String> mappedClaims)
      implements SourceReproductionResult {
    public Completed {
      if (candidate == null || sourcesCoordinate == null) {
        throw new IllegalArgumentException("Exact reproduction coordinates are required");
      }
      if (sourceRepositoryProvenance == null || sourceRepositoryProvenance.isBlank()) {
        throw new IllegalArgumentException("sourceRepositoryProvenance must be nonblank");
      }
      if (!SourceFileDigest.isCanonicalSha256(originalArchiveSha256)) {
        throw new IllegalArgumentException("originalArchiveSha256 must be a lowercase SHA-256");
      }
      if (!SourceFileDigest.isCanonicalSha256(sourcesArchiveSha256)) {
        throw new IllegalArgumentException("sourcesArchiveSha256 must be a lowercase SHA-256");
      }
      if (compilerIdentity == null || compilerIdentity.isBlank()) {
        throw new IllegalArgumentException("compilerIdentity must be nonblank");
      }
      compilerOptions = List.copyOf(compilerOptions);
      originalClassInventory = List.copyOf(originalClassInventory);
      sourceUnits = List.copyOf(sourceUnits);
      mappedClaims = Collections.unmodifiableMap(new TreeMap<>(mappedClaims));
    }
  }

  /** Diagnosed refusal to reproduce; it carries no approval value. */
  record Abstained(String rationale) implements SourceReproductionResult {
    public Abstained {
      if (rationale == null || rationale.isBlank()) {
        throw new IllegalArgumentException("rationale must be nonblank");
      }
    }
  }
}
