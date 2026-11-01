// WHY: Adds competing owners to a valid cache to exercise live ambiguity checks.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Mutates cached owner records for resolver-time conflict regressions. */
final class MavenStructuredProofOwnerCacheFixtures {
  private MavenStructuredProofOwnerCacheFixtures() {}

  /* default */ static void addStructuredOwner(
      final MavenCorroboratedSourceScenario.Prepared prepared, final boolean reverse)
      throws IOException {
    final List<OsvAdvisoryRecord> records = readRecords(prepared);
    if (records.stream().anyMatch(record -> "GHSA-race-structured-owner".equals(record.osvId()))) {
      return;
    }
    final OsvAdvisoryRecord owner = sourceOwner(records);
    final OsvAdvisoryRecord competitor =
        new OsvAdvisoryRecord(
            "GHSA-race-structured-owner",
            owner.modified(),
            Set.of(MavenCorroboratedSourceArchiveFixtures.CVE_ID),
            owner.affectedPackages(),
            owner.cnaAffectedEntries(),
            List.of(
                owner.evidence().stream()
                    .filter(StructuredSourceClassEvidence.class::isInstance)
                    .findFirst()
                    .orElseThrow()));
    writeWithCompetitor(prepared, records, competitor, reverse);
  }

  /* default */ static void addPackageOnlyOwner(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final boolean unknownScope,
      final boolean reverse)
      throws IOException {
    final List<OsvAdvisoryRecord> records = readRecords(prepared);
    if (records.stream().anyMatch(record -> "GHSA-race-package-owner".equals(record.osvId()))) {
      return;
    }
    final OsvAdvisoryRecord owner = sourceOwner(records);
    final OsvAffectedPackage original = owner.affectedPackages().getFirst();
    final OsvAffectedPackage competingPackage =
        new OsvAffectedPackage(
            original.ecosystem(),
            original.packageName(),
            original.coordinate(),
            unknownScope ? List.of() : List.of("2.0"),
            unknownScope
                ? List.of(new OsvAffectedRange("GIT", null, List.of(Map.of("introduced", "1.0"))))
                : List.of());
    final OsvAdvisoryRecord competitor =
        new OsvAdvisoryRecord(
            "GHSA-race-package-owner",
            owner.modified(),
            owner.aliases(),
            List.of(competingPackage),
            List.of(),
            List.of());
    writeWithCompetitor(prepared, records, competitor, reverse);
  }

  /* default */ static void addUnrelatedPackageOwner(
      final MavenCorroboratedSourceScenario.Prepared prepared) throws IOException {
    addPackageOwner(
        prepared,
        "GHSA-race-unrelated-package",
        new OsvAffectedPackage(
            "Maven",
            "org.other:library",
            ArtifactCoordinate.of("org.other", "library", null),
            List.of("2.0"),
            List.of()));
  }

  /* default */ static void addCaseVariantPackageOwner(
      final MavenCorroboratedSourceScenario.Prepared prepared) throws IOException {
    final List<OsvAdvisoryRecord> records = readRecords(prepared);
    final OsvAdvisoryRecord owner = sourceOwner(records);
    final OsvAffectedPackage original = owner.affectedPackages().getFirst();
    addPackageOwner(
        prepared,
        "GHSA-race-case-variant",
        new OsvAffectedPackage(
            original.ecosystem().toLowerCase(Locale.ROOT),
            original.packageName(),
            original.coordinate(),
            List.of("2.0"),
            List.of()));
  }

  private static void addPackageOwner(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final String ownerId,
      final OsvAffectedPackage affectedPackage)
      throws IOException {
    final List<OsvAdvisoryRecord> records = readRecords(prepared);
    if (records.stream().anyMatch(record -> ownerId.equals(record.osvId()))) {
      return;
    }
    final OsvAdvisoryRecord owner = sourceOwner(records);
    final OsvAdvisoryRecord competitor =
        new OsvAdvisoryRecord(
            ownerId,
            owner.modified(),
            owner.aliases(),
            List.of(affectedPackage),
            List.of(),
            List.of());
    writeWithCompetitor(prepared, records, competitor, false);
  }

  private static void writeWithCompetitor(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final List<OsvAdvisoryRecord> records,
      final OsvAdvisoryRecord competitor,
      final boolean reverse)
      throws IOException {
    final List<OsvAdvisoryRecord> updated = new ArrayList<>();
    if (reverse) {
      updated.add(competitor);
    }
    updated.addAll(records);
    if (!reverse) {
      updated.add(competitor);
    }
    MavenAssessmentFixtures.writeCacheRecords(prepared.cacheConfig().cacheDirectory(), updated);
  }

  private static List<OsvAdvisoryRecord> readRecords(
      final MavenCorroboratedSourceScenario.Prepared prepared) throws IOException {
    final Path index = prepared.cacheConfig().cacheDirectory().resolve("index.json");
    try (InputStream input = Files.newInputStream(index)) {
      return new VulnerabilityCacheEnvelopeReader()
          .read(input, MavenAssessmentFixtures.CACHE_PRODUCER)
          .records();
    }
  }

  private static OsvAdvisoryRecord sourceOwner(final List<OsvAdvisoryRecord> records) {
    return records.stream()
        .filter(record -> "GHSA-source".equals(record.osvId()))
        .findFirst()
        .orElseThrow();
  }
}
