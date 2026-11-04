// WHY: Renders validated persisted elision summaries without owning their file lifecycle.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/** Renders persisted elision summary rows as review text. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.NPathComplexity"
})
final class MavenElisionReportRenderer {
  /** Unit labels used for report byte totals. */
  private static final String[] BYTE_UNITS = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};

  /** Prefix used for nested report rows. */
  private static final String BULLET = "  - ";

  private MavenElisionReportRenderer() {}

  /** Lists tolerated duplicate classes with the action applied to their owning JARs. */
  static List<String> toleratedDuplicateLines(
      final List<MavenElisionReportSnapshot.ToleratedDuplicateClass> duplicates) {
    if (duplicates.isEmpty()) {
      return List.of();
    }
    final List<String> lines = new ArrayList<>();
    lines.add("Tolerated duplicate classes (accepted by configuration):");
    for (final MavenElisionReportSnapshot.ToleratedDuplicateClass duplicate : duplicates) {
      final String action =
          DuplicateClassPolicy.Action.RETAIN_JARS.name().equals(duplicate.action())
              ? "owning JARs retained whole"
              : "duplicate kept in every owner, other classes may be trimmed";
      lines.add(BULLET + duplicate.className() + ": " + action + " " + duplicate.owners());
    }
    return lines;
  }

  static List<String> render(final MavenElisionReportSnapshot snapshot) {
    final List<String> lines = new ArrayList<>();
    lines.add("Dependency Elider report");
    lines.add("Project: " + snapshot.projectGav());
    lines.add("Snapshot: last successful elide run at " + snapshot.generatedAt());
    lines.add("Analysis target JDK release: " + snapshot.executionEnvironment().targetRelease());
    lines.add("Elider runtime JDK release: " + snapshot.executionEnvironment().runtimeRelease());
    lines.add(
        "Policy: retained="
            + snapshot.policy().retainedArtifacts()
            + ", banished="
            + snapshot.policy().banishedDependencies());
    lines.add("The snapshot does not revalidate changed inputs when this goal runs.");
    lines.add(
        "Conventional Java source layout assumption saved for this run: "
            + snapshot.assumeConventionalJavaSourceLayout());
    lines.add(
        "Whole artifacts dropped: "
            + snapshot.wholeArtifactsDropped()
            + " (original JAR file bytes: "
            + formatBytes(snapshot.originalJarBytesDropped())
            + ")");
    lines.add(
        "Program classes removed with dropped JARs: "
            + snapshot.droppedProgramClassEntries()
            + " (uncompressed .class entry payload bytes: "
            + formatBytes(snapshot.droppedProgramClassBytes())
            + "; excludes module descriptors and archive sanitation metadata)");
    lines.add(
        "Raw trace decision drops before graph safety: " + snapshot.rawDroppedCoordinates().size());
    renderAppliedBans(snapshot.appliedBans(), lines);
    lines.addAll(toleratedDuplicateLines(snapshot.toleratedDuplicates()));
    for (final MavenElisionReportSnapshot.DroppedArtifact artifact : snapshot.droppedArtifacts()) {
      lines.add(
          BULLET
              + artifact.coordinate()
              + ": "
              + formatBytes(artifact.originalJarBytes())
              + " original JAR, "
              + artifact.programClassesRemoved()
              + " class entries, "
              + formatBytes(artifact.uncompressedProgramClassBytesRemoved()));
    }
    lines.add(
        "Program classes pruned from retained JARs: "
            + snapshot.programClassesPruned()
            + " (uncompressed omitted .class payload bytes: "
            + formatBytes(snapshot.uncompressedProgramClassBytesPruned())
            + "; excludes module descriptors and archive metadata)");
    for (final MavenElisionReportSnapshot.TrimmedArtifact artifact : snapshot.trimmedArtifacts()) {
      lines.add(
          BULLET
              + artifact.coordinate()
              + ": "
              + artifact.programClassesPruned()
              + " classes, "
              + formatBytes(artifact.uncompressedProgramClassBytesPruned()));
    }
    if (snapshot.removedCveComponents().isEmpty()) {
      lines.add("Advisories associated with removed components: none");
    } else {
      lines.add("Advisories associated with removed components:");
      for (final MavenElisionReportSnapshot.CveFinding finding : snapshot.removedCveComponents()) {
        lines.add(BULLET + finding.cveId() + " " + finding.coordinate());
      }
    }
    if (snapshot.provenAbsentCves().isEmpty()) {
      lines.add("Mitigated CVEs (vulnerable code pruned by trimming): none");
    } else {
      lines.add("Mitigated CVEs (vulnerable code pruned by trimming):");
      for (final MavenElisionReportSnapshot.CveFinding finding : snapshot.provenAbsentCves()) {
        lines.add(BULLET + finding.cveId() + " " + finding.coordinate());
      }
    }
    if (snapshot.inactivePreconditionCves().isEmpty()) {
      lines.add("CVEs inactive due to unmet prerequisite dependencies: none");
    } else {
      lines.add("CVEs inactive due to unmet prerequisite dependencies:");
      for (final MavenElisionReportSnapshot.CveFinding finding :
          snapshot.inactivePreconditionCves()) {
        final String causes =
            finding.missingPrerequisites().stream()
                .map(MavenMissingPrerequisite::displayText)
                .collect(Collectors.joining(", "));
        addWrapped(
            lines,
            BULLET
                + finding.cveId()
                + " "
                + finding.coordinate()
                + "; inactive because missing prerequisite dependencies: "
                + causes);
      }
    }
    if (snapshot.potentiallyConservativeCves().isEmpty()) {
      lines.add("Potentially conservative CVE exclusions: none detected");
    } else {
      lines.add("Potentially conservative CVE exclusions:");
      for (final MavenElisionReportSnapshot.ConservativeCveFinding finding :
          snapshot.potentiallyConservativeCves()) {
        lines.add(BULLET + finding.cveId() + " " + finding.coordinate());
        addWrapped(lines, "    Reason: " + finding.reason());
        addWrapped(
            lines,
            "    Actionable POM override to certify if absent classes do not apply to your"
                + " version:");
        for (final String overrideLine : finding.pomOverrideSnippet().split("\n")) {
          lines.add("      " + overrideLine);
        }
      }
    }
    renderSourceReviewFindings(snapshot.sourceReviewFindings(), lines);
    lines.addAll(MavenElisionReportAdvisoryRenderer.render(snapshot.advisoryReview()));
    lines.addAll(MavenElisionReportStructuredProofRenderer.render(snapshot));
    lines.addAll(ExclusionReviewRenderer.render(snapshot.exclusionReview()));
    lines.addAll(
        MediatedGraphReportRenderer.render(snapshot.mediatedGraph(), snapshot.projectGav()));
    return List.copyOf(lines);
  }

  private static void renderAppliedBans(
      final List<MavenElisionReportSnapshot.AppliedBan> bans, final List<String> lines) {
    if (bans.isEmpty()) {
      lines.add("Applied bans: none");
    } else {
      lines.add("Applied ban outcomes:");
      for (final MavenElisionReportSnapshot.AppliedBan ban : bans) {
        lines.add(
            BULLET
                + ban.dependency()
                + ": "
                + ban.status().toLowerCase(Locale.ROOT)
                + (ban.matchedArtifacts().isEmpty() ? "" : " " + ban.matchedArtifacts()));
      }
    }
  }

  private static void addWrapped(final List<String> lines, final String text) {
    lines.addAll(WordWrapFormatter.wrap(text, 80));
  }

  private static void renderSourceReviewFindings(
      final List<MavenElisionReportSnapshot.SourceReviewFinding> findings,
      final List<String> lines) {
    if (findings.isEmpty()) {
      return;
    }
    lines.add("Structured source claims (review only; verify before configuring a POM mapping):");
    for (final MavenElisionReportSnapshot.SourceReviewFinding finding : findings) {
      lines.add(
          BULLET
              + "OSV "
              + finding.osvId()
              + " "
              + finding.cveId()
              + " "
              + finding.coordinate()
              + " ["
              + finding.cnaAffectedEntryIdentity()
              + "]");
      lines.add("    Product: " + finding.affectedProductIdentity());
      lines.add(
          "    Source files: "
              + (finding.programFiles().isEmpty() ? "none" : finding.programFiles()));
      lines.add(
          "    Source routines: "
              + (finding.programRoutines().isEmpty() ? "none" : finding.programRoutines()));
      lines.add("    Conventional layout assumption saved: " + finding.conventionalLayoutAssumed());
      lines.add(
          "    Raw advisory applicability: "
              + finding.applicability()
              + " ("
              + finding.applicabilityRationale()
              + ")");
      if (finding.matches().isEmpty()) {
        lines.add("    SourceFile matches: none");
      } else {
        lines.add("    SourceFile match leads:");
        for (final MavenElisionReportSnapshot.SourceReviewMatch match : finding.matches()) {
          lines.add(
              "      "
                  + match.classEntry()
                  + " from "
                  + match.physicalJarEntry()
                  + " (tier "
                  + match.multiReleaseTier()
                  + ")");
        }
      }
      lines.add("    Review: " + finding.unresolvedRationale());
      addWrapped(
          lines,
          "    Verify the complete source-to-class mapping, then add an exact POM"
              + " vulnerableClasses assertion if confirmed; a filename match alone is incomplete.");
    }
  }

  static String formatBytes(final long bytes) {
    if (bytes < 0) {
      throw new IllegalArgumentException("bytes must not be negative");
    }
    double amount = bytes;
    int unit = 0;
    while (amount >= 1024.0 && unit < BYTE_UNITS.length - 1) {
      amount /= 1024.0;
      unit++;
    }
    return unit == 0
        ? bytes + " B"
        : String.format(Locale.ROOT, "%.2f %s", amount, BYTE_UNITS[unit]);
  }
}
