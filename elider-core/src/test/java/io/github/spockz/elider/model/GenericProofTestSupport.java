/* WHY: Builds generic claims for shared physical proof and serializer fixtures. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** Test-only conversion from fixture mappings to generic proof inputs. */
public final class GenericProofTestSupport {
  private GenericProofTestSupport() {}

  /** Builds a source-neutral finding from a test mapping. */
  public static GenericVulnerabilityFinding finding(final VulnerabilitySymbolMapping mapping) {
    final ArtifactCoordinate coordinate = mapping.affectedCoordinate();
    final Set<CodeClaim> code =
        mapping.vulnerableClasses().stream()
            .map(CodeReference::className)
            .map(CodeClaim::declared)
            .collect(Collectors.toUnmodifiableSet());
    final Set<PrerequisiteClaim> prerequisites =
        mapping.requiresDependency() == null
            ? Set.of()
            : Set.of(new PrerequisiteClaim(mapping.requiresDependency(), mapping.requiresClass()));
    return GenericVulnerabilityFinding.merge(
        List.of(
            new VulnerabilityFindingContribution(
                mapping.cveId(),
                Set.of(),
                coordinate.groupId(),
                coordinate.artifactId(),
                coordinate.type(),
                coordinate.classifier(),
                List.of(VersionCoverageClaim.affected(mapping.versionRangeSpec())),
                code.isEmpty() ? FieldValue.omitted() : FieldValue.supplied(code),
                prerequisites.isEmpty() ? FieldValue.omitted() : FieldValue.supplied(prerequisites),
                MergePriority.MANUAL,
                mapping.confidenceLevel() == ConfidenceLevel.HIGH
                    ? AssessmentIntent.AUTO_VERIFY
                    : AssessmentIntent.REVIEW_ONLY,
                "test mapping",
                Set.of())));
  }

  /** Executes generic class proof for an exact fixture mapping. */
  public static VexAttestation classProof(
      final VulnerabilitySymbolMapping mapping, final ArtifactTrimRecord record)
      throws IOException {
    return OmittedCodeProof.prove(finding(mapping), record, false);
  }

  /** Executes generic prerequisite proof for an exact fixture mapping. */
  public static VexAttestation prerequisiteProof(
      final VulnerabilitySymbolMapping mapping, final PreconditionClassInventory inventory)
      throws IOException {
    return PreconditionProof.prove(finding(mapping), mapping.affectedCoordinate(), inventory);
  }
}
