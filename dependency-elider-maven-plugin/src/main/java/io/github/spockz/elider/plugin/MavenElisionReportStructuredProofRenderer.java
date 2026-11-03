// WHY: Renders saved structured proof provenance without reopening analysis inputs.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.StructuredProofProvenance;
import io.github.spockz.elider.model.StructuredProofProvenance.ClassEntry;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Renders saved verified-proof provenance. */
final class MavenElisionReportStructuredProofRenderer {
  /** Indented bullet prefix used by report sections. */
  private static final String BULLET = "  - ";

  /** Total stable order across claim identity and every emitted class entry. */
  private static final Comparator<StructuredProofProvenance.ClaimAttribution> CLAIM_ORDER =
      Comparator.comparing(StructuredProofProvenance.ClaimAttribution::type)
          .thenComparing(StructuredProofProvenance.ClaimAttribution::claim)
          .thenComparing(StructuredProofProvenance.ClaimAttribution::sourceEntry)
          .thenComparing(
              StructuredProofProvenance.ClaimAttribution::routineOwnerBinaryName,
              Comparator.nullsFirst(Comparator.naturalOrder()))
          .thenComparing(
              StructuredProofProvenance.ClaimAttribution::emittedClasses,
              MavenElisionReportStructuredProofRenderer::compareEmittedClasses);

  private MavenElisionReportStructuredProofRenderer() {}

  /* default */ static List<String> render(final MavenElisionReportSnapshot snapshot) {
    if (snapshot.verifiedStructuredProofs().isEmpty()) {
      return List.of();
    }
    final List<String> lines = new ArrayList<>();
    lines.add("Verified structured source proofs (saved from the last successful elide run):");
    lines.add(
        "  Evidence is bounded to the recorded CNA claims and class absence; it does not"
            + " independently validate vulnerability status or CNA declaration completeness.");
    for (final MavenElisionReportSnapshot.VerifiedStructuredProofFinding finding :
        snapshot.verifiedStructuredProofs()) {
      final StructuredProofProvenance provenance = finding.provenance();
      lines.add(BULLET + finding.cveId() + " " + finding.coordinate());
      lines.add("    Generated at: " + snapshot.generatedAt());
      lines.add("    Original archive SHA-256: " + finding.originalSha256());
      lines.add("    Trimmed archive SHA-256: " + finding.trimmedSha256());
      lines.add("    CNA record SHA-256: " + provenance.cveSourceSha256());
      lines.add(
          "    CNA product: "
              + provenance.affectedProductIdentity()
              + " ("
              + provenance.cnaAffectedEntryIdentity()
              + ")");
      lines.add("    OSV record: " + provenance.osvId());
      lines.add(
          "    OSV source authority: configured producer-compatible typed index; raw package "
              + provenance.rawScopeEvidence().osvEcosystem()
              + "/"
              + provenance.rawScopeEvidence().osvPackageName()
              + ", versions="
              + provenance.rawScopeEvidence().osvVersions()
              + ", ranges="
              + provenance.rawScopeEvidence().osvRanges());
      lines.add(
          "    Sources artifact: "
              + provenance.sourcesCoordinate()
              + " SHA-256="
              + provenance.sourcesArchiveSha256()
              + " repository="
              + provenance.sourceRepositoryProvenance());
      lines.add(
          "    Compiler: "
              + provenance.compilerIdentity()
              + " options="
              + provenance.compilerOptions()
              + "; conventional layout assumed="
              + provenance.conventionalLayoutAssumed());
      provenance.claimAttributions().stream()
          .sorted(CLAIM_ORDER)
          .forEach(
              claim ->
                  lines.add(
                      "    Claim "
                          + claim.type()
                          + " "
                          + claim.claim()
                          + (claim.routineOwnerBinaryName() == null
                              ? ""
                              : " declared by " + claim.routineOwnerBinaryName())
                          + " from "
                          + claim.sourceEntry()
                          + " emits "
                          + claim.emittedClasses()));
    }
    return List.copyOf(lines);
  }

  private static int compareEmittedClasses(
      final List<ClassEntry> left, final List<ClassEntry> right) {
    final int sharedLength = Math.min(left.size(), right.size());
    for (int index = 0; index < sharedLength; index++) {
      final ClassEntry leftEntry = left.get(index);
      final ClassEntry rightEntry = right.get(index);
      final int pathOrder = leftEntry.path().compareTo(rightEntry.path());
      if (pathOrder != 0) {
        return pathOrder;
      }
      final int digestOrder = leftEntry.sha256().compareTo(rightEntry.sha256());
      if (digestOrder != 0) {
        return digestOrder;
      }
    }
    return Integer.compare(left.size(), right.size());
  }
}
