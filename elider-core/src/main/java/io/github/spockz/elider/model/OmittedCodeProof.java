/* WHY: This package controls creation of immutable VEX proof evidence. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.scanner.JarSourceFileIndex;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Proves mapped classes are absent from physical archives. */
@SuppressWarnings("PMD.LawOfDemeter")
public final class OmittedCodeProof {
  private OmittedCodeProof() {}

  /** Captures exact archive observations once for all findings on a trimmed artifact. */
  public static ArchiveInspection inspect(final ArtifactTrimRecord record) throws IOException {
    Objects.requireNonNull(record, "record");
    final JarSourceFileIndex original = JarSourceFileIndex.read(record.originalPath());
    final ArtifactDigests trimmed = ArtifactDigests.read(record.trimmedPath());
    if (!original.archiveSha256().equals(record.originalSha256())
        || !trimmed.sha256().equals(record.trimmedSha256())) {
      throw new IllegalArgumentException("Artifact digest no longer matches trim record");
    }
    return new ArchiveInspection(
        record, original, OmittedArchiveClassInventory.read(record.trimmedPath()));
  }

  /** Inspects archives and verifies every effective declared code locator. */
  public static VexAttestation prove(
      final GenericVulnerabilityFinding finding,
      final ArtifactTrimRecord record,
      final boolean assumeConventionalJavaSourceLayout)
      throws IOException {
    return prove(finding, inspect(record), assumeConventionalJavaSourceLayout);
  }

  /** Uses controlled artifact observations for attribution. */
  public static VexAttestation prove(
      final GenericVulnerabilityFinding finding,
      final ArchiveInspection inspection,
      final boolean assumeConventionalJavaSourceLayout) {
    Objects.requireNonNull(inspection, "inspection");
    final ArtifactTrimRecord record = inspection.record;
    FindingVerification.requireEligible(finding, record.coordinate());
    if (finding.codeGroupStatusFor(record.coordinate().version()) != ClaimGroupStatus.DECLARED) {
      throw new IllegalArgumentException("Physical omission requires effective declared code");
    }
    final CodeAttributionResolver.Result attribution =
        CodeAttributionResolver.resolve(
            finding.effectiveCodeClaimsFor(record.coordinate().version()),
            inspection.originalIndex,
            assumeConventionalJavaSourceLayout);
    if (attribution.declarations().isEmpty()
        || attribution.declarations().stream()
            .anyMatch(
                declaration -> declaration.status() != CodeAttributionResolver.Status.RESOLVED)) {
      throw new IllegalArgumentException("Declared code attribution is incomplete: " + attribution);
    }
    final Set<String> declaredClasses = new TreeSet<>();
    attribution
        .declarations()
        .forEach(declaration -> declaredClasses.addAll(declaration.classFamily()));
    final Set<String> originalClasses =
        inspection.originalIndex.classFiles().stream()
            .map(value -> value.classEntry().replace('.', '/'))
            .collect(java.util.stream.Collectors.toSet());
    final Set<String> absent =
        PhysicalOmissionChecks.verifySymbols(
            declaredClasses, originalClasses, inspection.trimmedClasses);
    return VexAttestation.genericOmittedCode(
        finding,
        record.coordinate(),
        "All effective declared code and its nested classes are absent from the trimmed artifact. "
            + "This observation is limited to the declared code and does not establish "
            + "declaration completeness.",
        absent,
        record.originalSha256(),
        record.trimmedSha256());
  }

  /** Observations bound to original and resulting archive digests. */
  @SuppressWarnings({"PMD.CommentRequired", "PMD.AvoidFieldNameMatchingMethodName"})
  public static final class ArchiveInspection {
    private final ArtifactTrimRecord record;
    private final JarSourceFileIndex originalIndex;
    private final Set<String> trimmedClasses;

    private ArchiveInspection(
        final ArtifactTrimRecord record,
        final JarSourceFileIndex originalIndex,
        final Set<String> trimmedClasses) {
      this.record = record;
      this.originalIndex = originalIndex;
      this.trimmedClasses = Set.copyOf(trimmedClasses);
    }

    /** Returns attribution data without granting proof authority. */
    public JarSourceFileIndex originalIndex() {
      return originalIndex;
    }
  }
}
