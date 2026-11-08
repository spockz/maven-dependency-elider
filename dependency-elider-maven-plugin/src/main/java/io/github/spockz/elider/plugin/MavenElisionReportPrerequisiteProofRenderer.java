/* WHY: Renders detached prerequisite observations without implying proof authority. */

package io.github.spockz.elider.plugin;

import java.util.List;

/** Formats detached proof observations in the text report. */
final class MavenElisionReportPrerequisiteProofRenderer {
  /** Prevents creating mutable renderer instances. */
  private MavenElisionReportPrerequisiteProofRenderer() {}

  /* package */ static void append(
      final List<String> lines, final PrerequisiteProofEvidence evidence) {
    lines.add(
        "    Prerequisite proof evidence: final inventory " + evidence.finalInventoryFingerprint());
    if (evidence.baselineDetail() != null) {
      lines.add("      Baseline attribution: " + evidence.baselineDetail());
    }
    for (final PrerequisiteProofEvidence.GroupEvidence group : evidence.groups()) {
      lines.add("      " + group.group().operator() + " group attribution: " + group.attribution());
      for (final PrerequisiteProofEvidence.MemberEvidence member : group.members()) {
        lines.add(
            "        "
                + member.claim().requiresDependency()
                + " / "
                + member.claim().requiresClass()
                + "="
                + member.state()
                + " ("
                + member.attribution()
                + ")");
        for (final PrerequisiteProofEvidence.ProviderEvidence provider : member.providers()) {
          lines.add(
              "          Provider "
                  + (provider.coordinate() == null ? provider.kind() : provider.coordinate())
                  + ": "
                  + provider.attribution()
                  + "; baseline="
                  + provider.baselinePath()
                  + "; final="
                  + provider.finalPath());
        }
      }
    }
  }
}
