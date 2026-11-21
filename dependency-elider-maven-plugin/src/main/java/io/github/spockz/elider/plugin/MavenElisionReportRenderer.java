// WHY: Renders validated persisted elision summaries without owning their file lifecycle.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Renders persisted elision summary rows as review text. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.GodClass"})
final class MavenElisionReportRenderer {
  /** Unit labels used for report byte totals. */
  private static final String[] BYTE_UNITS = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};

  /** Prefix used for nested report rows. */
  private static final String BULLET = "  - ";

  /** Label for values that the saved observation cannot establish. */
  private static final String UNKNOWN = "unknown";

  /** Maximum number of pruned class names printed inline per artifact on console. */
  private static final int MAX_CONSOLE_CLASS_PREVIEW = 5;

  private MavenElisionReportRenderer() {}

  /** Lists tolerated duplicate classes with the action applied to their owning JARs. */
  static List<String> toleratedDuplicateLines(
      final List<MavenElisionReportSnapshot.ToleratedDuplicateClass> duplicates) {
    return toleratedDuplicateLines(duplicates, false);
  }

  private static List<String> toleratedDuplicateLines(
      final List<MavenElisionReportSnapshot.ToleratedDuplicateClass> duplicates,
      final boolean predicted) {
    if (duplicates.isEmpty()) {
      return List.of();
    }
    final List<String> lines = new ArrayList<>();
    lines.add("Tolerated duplicate classes (accepted by configuration):");
    for (final MavenElisionReportSnapshot.ToleratedDuplicateClass duplicate : duplicates) {
      final String action =
          DuplicateClassPolicy.Action.RETAIN_JARS.name().equals(duplicate.action())
              ? (predicted ? "owning JARs would be retained whole" : "owning JARs retained whole")
              : (predicted
                  ? "duplicate would be kept in every owner, other classes may be trimmed"
                  : "duplicate kept in every owner, other classes may be trimmed");
      lines.add(BULLET + duplicate.className() + ": " + action + " " + duplicate.owners());
    }
    return lines;
  }

  @SuppressWarnings({
    "PMD.CyclomaticComplexity",
    "PMD.NPathComplexity"
  }) // One pass formats all captured sections.
  static List<String> render(final MavenElisionReportSnapshot snapshot) {
    final List<String> lines = new ArrayList<>();
    final boolean predicted = snapshot.mode() == MavenElisionReportSnapshot.Mode.ANALYSIS;
    lines.add("Dependency Elider report");
    lines.add("Project: " + snapshot.projectGav());
    lines.add(
        "Snapshot: "
            + (predicted ? "analysis prediction" : "last successful elide run")
            + " at "
            + snapshot.generatedAt());
    lines.add("Analysis target JDK release: " + snapshot.executionEnvironment().targetRelease());
    lines.add("Elider runtime JDK release: " + snapshot.executionEnvironment().runtimeRelease());
    renderRuntimeCoverage(snapshot.executionEnvironment().runtimeCoverage(), lines);
    lines.add(
        "Policy: retained="
            + snapshot.policy().retainedArtifacts()
            + ", banished="
            + snapshot.policy().banishedDependencies());
    lines.add("The snapshot does not revalidate changed inputs when this goal runs.");
    if (snapshot.sourceAttributionFallback() != null) {
      lines.add("Source attribution fallback: " + snapshot.sourceAttributionFallback());
    }
    lines.add(
        "Conventional Java source layout assumption saved for this run: "
            + snapshot.assumeConventionalJavaSourceLayout());
    lines.add(
        (predicted ? "Whole artifacts that would be dropped: " : "Whole artifacts dropped: ")
            + snapshot.wholeArtifactsDropped()
            + " / "
            + snapshot.inputArtifactCount()
            + " (original JAR file bytes: "
            + formatBytes(snapshot.originalJarBytesDropped())
            + ")");
    lines.add(
        (predicted
                ? "Program classes that would be removed with dropped JARs: "
                : "Program classes removed with dropped JARs: ")
            + snapshot.droppedProgramClassEntries()
            + " (uncompressed .class entry payload bytes: "
            + formatBytes(snapshot.droppedProgramClassBytes())
            + "; excludes module descriptors and archive sanitation metadata)");
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
        "Raw trace decision drops before graph safety: " + snapshot.rawDroppedCoordinates().size());
    renderAppliedBans(snapshot.appliedBans(), lines, predicted);
    lines.addAll(toleratedDuplicateLines(snapshot.toleratedDuplicates(), predicted));
    lines.add(
        (predicted
                ? "Program classes that would be pruned from retained JARs: "
                : "Program classes pruned from retained JARs: ")
            + snapshot.programClassesPruned()
            + " (uncompressed omitted .class payload bytes: "
            + (snapshot.uncompressedProgramClassBytesPruned() == null
                ? UNKNOWN
                : formatBytes(snapshot.uncompressedProgramClassBytesPruned()))
            + "; excludes module descriptors and archive metadata)");
    for (final MavenElisionReportSnapshot.TrimmedArtifact artifact : snapshot.trimmedArtifacts()) {
      lines.add(
          BULLET
              + artifact.coordinate()
              + ": "
              + artifact.programClassesPruned()
              + " classes, "
              + (artifact.uncompressedProgramClassBytesPruned() == null
                  ? UNKNOWN
                  : formatBytes(artifact.uncompressedProgramClassBytesPruned())));
      if (predicted && artifact.plannedClasses() != null && !artifact.plannedClasses().isEmpty()) {
        lines.add(
            "    Classes that would be pruned from this JAR: "
                + formatClassPreview(artifact.plannedClasses()));
      }
    }
    lines.addAll(
        MavenElisionReportGenericRenderer.render(
            snapshot.genericFindings(), snapshot.sourceObservations(), predicted));
    lines.addAll(catalogAdoptionLines(snapshot.catalogAdoptions()));
    renderForbiddenCode(snapshot.forbiddenCodeAssessments(), lines);
    lines.addAll(ExclusionReviewRenderer.render(snapshot.exclusionReview()));
    lines.addAll(
        MediatedGraphReportRenderer.render(
            snapshot.mediatedGraph(), snapshot.projectGav(), predicted));
    return List.copyOf(lines);
  }

  private static void renderRuntimeCoverage(
      final MavenRuntimeCoverage coverage, final List<String> lines) {
    lines.add("Analyzed runtime releases: " + coverage.analyzedReleases());
    for (final MavenRuntimeCoverage.Image image : coverage.inputs()) {
      lines.add(
          "Runtime input "
              + image.path()
              + ": "
              + (image.problem() == null
                  ? "Java "
                      + image.version()
                      + " ("
                      + java.util.Objects.toString(image.vendor(), "vendor unknown")
                      + ")"
                  : image.problem()));
      if (image.linkageProblem() != null) {
        lines.add("    Runtime linkage unavailable: " + image.linkageProblem());
      }
    }
    if (coverage.compilerTargetWarning() != null) {
      lines.add("WARNING: " + coverage.compilerTargetWarning());
    }
  }

  /* package */ static void renderForbiddenCode(
      final List<ForbiddenCodeAssessment> assessments, final List<String> lines) {
    assessments.stream()
        .map(ForbiddenCodeAssessment::status)
        .max(java.util.Comparator.comparingInt(MavenElisionReportRenderer::policySeverity))
        .ifPresent(status -> lines.add("Forbidden code overall: " + status));
    for (final ForbiddenCodeAssessment assessment : assessments) {
      lines.add(
          "Forbidden code "
              + assessment.mode()
              + " "
              + assessment.status()
              + ": "
              + assessment.cveId()
              + " "
              + assessment.symbol()
              + " in "
              + assessment.componentKind()
              + " "
              + java.util.Objects.toString(assessment.componentIdentity(), UNKNOWN)
              + " ("
              + assessment.reason()
              + "; enforcement "
              + (assessment.enforcementEnabled() ? "enabled" : "disabled")
              + ")");
      lines.add(
          "    scope="
              + assessment.versionScope()
              + ", version="
              + java.util.Objects.toString(assessment.componentVersion(), UNKNOWN)
              + ", targetRelease="
              + java.util.Objects.toString(assessment.targetRelease(), UNKNOWN)
              + ", applicability="
              + assessment.versionApplicability()
              + ", assertsAffected="
              + assessment.assertsAffected()
              + ", evidence="
              + assessment.evidenceKind()
              + ", complete="
              + assessment.complete()
              + ", provider="
              + java.util.Objects.toString(assessment.provider(), UNKNOWN)
              + ", provenance="
              + assessment.provenance()
              + (assessment.sourceUrl() == null ? "" : ", source=" + assessment.sourceUrl()));
      for (final ForbiddenCodeAssessment.Match match : assessment.matches()) {
        lines.add(
            "    provider="
                + match.provider()
                + ", entry="
                + match.entry()
                + ", tier="
                + match.tier()
                + ", owner="
                + match.resolvedOwner()
                + ", descriptors="
                + match.descriptors());
      }
    }
  }

  private static int policySeverity(final ForbiddenCodeAssessment.Status status) {
    return switch (status) {
      case NOT_APPLICABLE -> 0;
      case PASS -> 1;
      case UNKNOWN -> 2;
      case VIOLATION -> 3;
    };
  }

  private static String formatClassPreview(final List<String> classes) {
    if (classes.size() <= MAX_CONSOLE_CLASS_PREVIEW) {
      return classes.toString();
    }
    final int remaining = classes.size() - MAX_CONSOLE_CLASS_PREVIEW;
    return "["
        + String.join(", ", classes.subList(0, MAX_CONSOLE_CLASS_PREVIEW))
        + ", ... (+"
        + remaining
        + " more in analysis report)]";
  }

  private static List<String> catalogAdoptionLines(
      final List<MavenVulnerabilityMappingCatalogResolver.Adoption> adoptions) {
    if (adoptions.isEmpty()) {
      return List.of();
    }
    final List<String> lines = new ArrayList<>();
    lines.add("Adopted vulnerability mapping catalogs:");
    for (final MavenVulnerabilityMappingCatalogResolver.Adoption adoption : adoptions) {
      lines.add(
          BULLET
              + adoption.coordinate()
              + " (catalogId="
              + adoption.catalogId()
              + ", sha256="
              + adoption.sha256()
              + ", mappings="
              + adoption.mappingIds().size()
              + ", unresolved="
              + adoption.unresolvedMappingIds().size()
              + ")");
      for (final String diagnostic : adoption.diagnostics()) {
        lines.add("    Diagnostic: " + diagnostic);
      }
    }
    return List.copyOf(lines);
  }

  private static void renderAppliedBans(
      final List<MavenElisionReportSnapshot.AppliedBan> bans,
      final List<String> lines,
      final boolean predicted) {
    if (bans.isEmpty()) {
      lines.add((predicted ? "Planned" : "Applied") + " bans: none");
    } else {
      lines.add((predicted ? "Planned" : "Applied") + " ban outcomes:");
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
