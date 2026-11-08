/* WHY: Labels Analyze forecasts so report readers do not mistake them for verified output. */

package io.github.spockz.elider.plugin;

import java.util.List;

/** Renders the detached, non-authoritative prerequisite forecast. */
final class MavenElisionReportPrerequisitePredictionRenderer {
  private MavenElisionReportPrerequisitePredictionRenderer() {}

  /* package */ static void append(
      final List<String> lines, final PrerequisitePrediction prediction) {
    lines.add("    Planned prerequisite forecast (not verified against output bytes):");
    for (final PrerequisitePrediction.GroupForecast group : prediction.groups()) {
      lines.add("      " + group.group().operator() + " disarmed=" + group.disarmed());
      for (final PrerequisitePrediction.MemberForecast member : group.members()) {
        lines.add(
            "        "
                + member.claim().requiresDependency()
                + " / "
                + member.claim().requiresClass()
                + ": "
                + member.state()
                + " ("
                + member.reason()
                + ")");
      }
    }
    if (prediction.detail() != null) {
      lines.add("      Forecast detail: " + prediction.detail());
    }
  }
}
