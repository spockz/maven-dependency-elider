// WHY: Renders saved structured proof provenance without reopening analysis inputs.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.StructuredProofProvenance;
import java.util.ArrayList;
import java.util.List;

/** Renders saved verified-proof provenance. */
final class MavenElisionReportStructuredProofRenderer {
  /** Indented bullet prefix used by report sections. */
  private static final String BULLET = "  - ";

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
          .sorted()
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
}
