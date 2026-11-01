// WHY: Mutates cache evidence to prove structured proof always rebinds current raw inputs.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.AdvisoryEvidence;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Produces producer-compatible cache variants for structured proof regressions. */
final class MavenStructuredProofCacheFixtures {
  private MavenStructuredProofCacheFixtures() {}

  /* default */ static void setOsvAffectedVersions(
      final MavenCorroboratedSourceScenario.Prepared prepared, final List<String> versions)
      throws IOException {
    final List<OsvAdvisoryRecord> records = readRecords(prepared);
    MavenAssessmentFixtures.writeCacheRecords(
        prepared.cacheConfig().cacheDirectory(),
        records.stream().map(record -> replacePackageVersions(record, versions)).toList());
  }

  /* default */ static void setPersistedFileClassAttribution(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final String fileClaim,
      final String claimedClass)
      throws IOException {
    final List<OsvAdvisoryRecord> records = readRecords(prepared);
    MavenAssessmentFixtures.writeCacheRecords(
        prepared.cacheConfig().cacheDirectory(),
        records.stream()
            .map(record -> replacePersistedClassAttribution(record, fileClaim, claimedClass))
            .toList());
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

  private static OsvAdvisoryRecord replacePersistedClassAttribution(
      final OsvAdvisoryRecord record, final String fileClaim, final String claimedClass) {
    final List<AdvisoryEvidence> evidence =
        record.evidence().stream()
            .map(
                item -> {
                  if (item instanceof StructuredSourceClassEvidence structured
                      && structured.programFiles().contains(fileClaim)) {
                    return new StructuredSourceClassEvidence(
                        structured.scope(),
                        structured.provenance(),
                        structured.cnaAffectedEntryIdentity(),
                        structured.affectedProductIdentity(),
                        structured.programFiles(),
                        structured.programRoutines(),
                        persistedClassAttribution(structured, fileClaim, claimedClass),
                        structured.routineClassAttribution());
                  }
                  return item;
                })
            .toList();
    return copyRecord(record, record.affectedPackages(), evidence);
  }

  private static Map<String, Set<String>> persistedClassAttribution(
      final StructuredSourceClassEvidence evidence,
      final String fileClaim,
      final String claimedClass) {
    return evidence.programFiles().stream()
        .collect(
            Collectors.toMap(
                claim -> claim,
                claim ->
                    claim.equals(fileClaim)
                        ? Set.of(claimedClass)
                        : evidence.fileClassAttribution().get(claim)));
  }

  private static OsvAdvisoryRecord replacePackageVersions(
      final OsvAdvisoryRecord record, final List<String> versions) {
    final List<OsvAffectedPackage> affectedPackages =
        record.affectedPackages().stream()
            .map(
                affected ->
                    new OsvAffectedPackage(
                        affected.ecosystem(),
                        affected.packageName(),
                        affected.coordinate(),
                        versions,
                        List.of()))
            .toList();
    return copyRecord(record, affectedPackages, record.evidence());
  }

  private static OsvAdvisoryRecord copyRecord(
      final OsvAdvisoryRecord record,
      final List<OsvAffectedPackage> packages,
      final List<AdvisoryEvidence> evidence) {
    return new OsvAdvisoryRecord(
        record.osvId(),
        record.modified(),
        record.aliases(),
        packages,
        record.cnaAffectedEntries(),
        evidence);
  }
}
