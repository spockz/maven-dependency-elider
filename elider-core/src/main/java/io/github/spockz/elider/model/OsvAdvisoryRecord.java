/* WHY: Keeps every cacheable advisory item owned by its original OSV record. */

package io.github.spockz.elider.model;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** One active OSV record and all review-only evidence indexed from that record. */
public record OsvAdvisoryRecord(
    String osvId,
    String modified,
    Set<String> aliases,
    List<OsvAffectedPackage> affectedPackages,
    List<CveAffectedEntryContext> cnaAffectedEntries,
    List<AdvisoryEvidence> evidence) {
  /** Exactly one source entry must own structured attribution. */
  private static final int ONE_MATCHING_CNA_ENTRY = 1;

  /** Validates record identity and freezes aliases and evidence. */
  public OsvAdvisoryRecord {
    if (osvId == null || osvId.isBlank()) {
      throw new IllegalArgumentException("osvId must not be blank");
    }
    Objects.requireNonNull(modified, "modified");
    try {
      java.time.Instant.parse(modified);
    } catch (final java.time.format.DateTimeParseException exception) {
      throw new IllegalArgumentException("modified must be an RFC 3339 timestamp", exception);
    }
    Objects.requireNonNull(aliases, "aliases");
    final Set<String> aliasCopy = new TreeSet<>();
    for (final String alias : aliases) {
      if (alias == null || alias.isBlank()) {
        throw new IllegalArgumentException("aliases must contain non-blank values");
      }
      aliasCopy.add(alias);
    }
    aliasCopy.remove(osvId);
    aliases = Set.copyOf(aliasCopy);
    Objects.requireNonNull(affectedPackages, "affectedPackages");
    affectedPackages.forEach(value -> Objects.requireNonNull(value, "affected package"));
    affectedPackages = List.copyOf(affectedPackages);
    Objects.requireNonNull(cnaAffectedEntries, "cnaAffectedEntries");
    cnaAffectedEntries.forEach(value -> Objects.requireNonNull(value, "CNA affected entry"));
    cnaAffectedEntries = List.copyOf(cnaAffectedEntries);
    Objects.requireNonNull(evidence, "evidence");
    evidence.forEach(item -> Objects.requireNonNull(item, "evidence item"));
    evidence = List.copyOf(evidence);
    for (final AdvisoryEvidence item : evidence) {
      final AdvisoryScope scope = item.scope();
      if (scope.cveId() != null
          && !scope.cveId().equals(osvId)
          && !aliases.contains(scope.cveId())) {
        throw new IllegalArgumentException("Evidence CVE scope must be owned by this OSV record");
      }
      final String packageKey =
          scope.affectedCoordinate().groupId() + ":" + scope.affectedCoordinate().artifactId();
      if (affectedPackages.stream()
          .noneMatch(
              affectedPackage ->
                  affectedPackage.ecosystem().equals(scope.ecosystem())
                      && affectedPackage.packageName().equals(scope.packageName())
                      && affectedPackage.coordinate().toShortKey().equals(packageKey))) {
        throw new IllegalArgumentException("Evidence scope must match an OSV affected package");
      }
      final String sourceId = item.provenance().sourceRecordId();
      final boolean ownedSource =
          switch (item.provenance().origin()) {
            case OSV -> sourceId.equals(osvId);
            case DESCRIPTION, REFERENCE_URL ->
                sourceId.startsWith(osvId + "#")
                    || aliases.stream().anyMatch(alias -> sourceId.startsWith(alias + "#"));
            case CVE_LIST ->
                scope.cveId() != null
                    && sourceId.equals(scope.cveId())
                    && (sourceId.equals(osvId) || aliases.contains(sourceId));
            case POM -> false;
          };
      if (!ownedSource) {
        throw new IllegalArgumentException("Evidence provenance must belong to this OSV record");
      }
      if (item instanceof StructuredSourceClassEvidence structured) {
        validateStructuredEntryLink(structured, cnaAffectedEntries);
      } else if (item instanceof CorroboratedSourceClassCandidate corroborated) {
        validateCorroboratedEntryLink(corroborated, cnaAffectedEntries);
      }
    }
  }

  private static void validateStructuredEntryLink(
      final StructuredSourceClassEvidence evidence, final List<CveAffectedEntryContext> entries) {
    final List<CveAffectedEntryContext> matches =
        entries.stream()
            .filter(entry -> entry.entryIdentity().equals(evidence.cnaAffectedEntryIdentity()))
            .toList();
    if (matches.size() != ONE_MATCHING_CNA_ENTRY) {
      throw new IllegalArgumentException(
          "Structured evidence must identify one CNA affected entry");
    }
    final CveAffectedEntryContext entry = matches.getFirst();
    final String packageUrl =
        "pkg:maven/"
            + evidence.scope().affectedCoordinate().groupId()
            + "/"
            + evidence.scope().affectedCoordinate().artifactId();
    final String productIdentity =
        (entry.vendor() == null ? "" : entry.vendor()) + ":" + entry.product();
    if (!packageUrl.equals(entry.packageUrl())
        || !productIdentity.equals(evidence.affectedProductIdentity())
        || !entry.programFiles().equals(evidence.programFiles())
        || !entry.programRoutines().equals(evidence.programRoutines())) {
      throw new IllegalArgumentException(
          "Structured evidence must retain its exact CNA entry claims");
    }
  }

  private static void validateCorroboratedEntryLink(
      final CorroboratedSourceClassCandidate candidate,
      final List<CveAffectedEntryContext> entries) {
    final List<CveAffectedEntryContext> matches =
        entries.stream()
            .filter(entry -> entry.entryIdentity().equals(candidate.cnaAffectedEntryIdentity()))
            .toList();
    if (matches.size() != ONE_MATCHING_CNA_ENTRY) {
      throw new IllegalArgumentException(
          "Corroborated candidate must identify one CNA affected entry");
    }
    final CveAffectedEntryContext entry = matches.getFirst();
    final String packageUrl =
        "pkg:maven/"
            + candidate.artifactCoordinate().groupId()
            + "/"
            + candidate.artifactCoordinate().artifactId();
    final String productIdentity =
        (entry.vendor() == null ? "" : entry.vendor()) + ":" + entry.product();
    if (!packageUrl.equals(entry.packageUrl())
        || !productIdentity.equals(candidate.affectedProductIdentity())
        || !entry.programFiles().contains(candidate.programFile())
        || !entry.hasUnambiguousExactAffectedVersion(candidate.artifactCoordinate().version())) {
      throw new IllegalArgumentException(
          "Corroborated candidate must retain one exact CNA product/version claim");
    }
  }
}
