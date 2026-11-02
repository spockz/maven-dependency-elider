// WHY: Turns review-only heuristic candidates into explicitly conditional Maven mapping drafts.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.List;

/** Formats conditional POM mapping suggestions from heuristic advisory rows. */
final class MavenHeuristicPomMappingSnippet {
  /** Base indentation for generated XML. */
  private static final String INDENT = "  ";

  /** Indentation for fields nested directly in a vulnerability mapping. */
  private static final String FIELD_INDENT = INDENT + INDENT;

  /** Indentation for classes nested in a mapping's class list. */
  private static final String CLASS_INDENT = FIELD_INDENT + INDENT;

  private MavenHeuristicPomMappingSnippet() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static List<String> render(final MavenElisionReportSnapshot.HeuristicAdvisoryFinding finding) {
    if (finding.cveId() == null
        || finding.sourceUrl() == null
        || finding.candidateClasses().isEmpty()
        || !finding.candidateDependencies().contains(finding.packageName())) {
      return List.of();
    }

    final ArtifactCoordinate coordinate =
        MavenElisionReportSourceCoordinateValidator.parseCanonical(finding.coordinate());
    final StringBuilder xml = new StringBuilder(512);
    xml.append("<vulnerabilityMappings>\n").append(INDENT).append("<vulnerabilityMapping>\n");
    appendXmlElement(xml, FIELD_INDENT, "cveId", finding.cveId());
    appendXmlElement(xml, FIELD_INDENT, "groupId", coordinate.groupId());
    appendXmlElement(xml, FIELD_INDENT, "artifactId", coordinate.artifactId());
    appendXmlElement(xml, FIELD_INDENT, "versionRangeSpec", "[" + coordinate.version() + "]");
    xml.append(FIELD_INDENT).append("<vulnerableClasses>\n");
    for (final String className : finding.candidateClasses()) {
      appendXmlElement(xml, CLASS_INDENT, "vulnerableClass", className);
    }
    xml.append(FIELD_INDENT).append("</vulnerableClasses>\n");
    appendXmlElement(xml, FIELD_INDENT, "sourceAdvisoryUrl", finding.sourceUrl());
    xml.append(FIELD_INDENT)
        .append("<confidenceLevel>HIGH</confidenceLevel>\n")
        .append(INDENT)
        .append("</vulnerabilityMapping>\n</vulnerabilityMappings>");
    return xml.toString().lines().toList();
  }

  private static void appendXmlElement(
      final StringBuilder xml, final String indentation, final String element, final String value) {
    xml.append(indentation)
        .append('<')
        .append(element)
        .append('>')
        .append(escapeXml(value))
        .append("</")
        .append(element)
        .append(">\n");
  }

  private static String escapeXml(final String value) {
    return value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;");
  }
}
