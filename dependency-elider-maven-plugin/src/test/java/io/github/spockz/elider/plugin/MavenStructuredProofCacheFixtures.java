// WHY: Mutates cache evidence to prove structured proof always rebinds current raw inputs.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.AdvisoryEvidence;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
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

  /* default */ static void addHeuristicEvidence(
      final MavenCorroboratedSourceScenario.Prepared prepared) throws IOException {
    final List<OsvAdvisoryRecord> records = readRecords(prepared);
    final List<OsvAdvisoryRecord> updated =
        records.stream()
            .map(
                record -> {
                  if (!record.aliases().contains(MavenCorroboratedSourceArchiveFixtures.CVE_ID)) {
                    return record;
                  }
                  final List<AdvisoryEvidence> evidence =
                      new java.util.ArrayList<>(record.evidence());
                  evidence.add(
                      new HeuristicCandidateEvidence(
                          record.evidence().stream()
                              .filter(StructuredSourceClassEvidence.class::isInstance)
                              .map(StructuredSourceClassEvidence.class::cast)
                              .findFirst()
                              .orElseThrow()
                              .scope(),
                          new AdvisoryProvenance(
                              EvidenceOrigin.REFERENCE_URL,
                              record.osvId() + "#reference:race",
                              URI.create("https://example.invalid/reference"),
                              "d".repeat(64)),
                          Set.of("org.example.HeuristicOnly"),
                          Set.of(
                              MavenCorroboratedSourceArchiveFixtures.GROUP_ID
                                  + ":"
                                  + MavenCorroboratedSourceArchiveFixtures.ARTIFACT_ID)));
                  return copyRecord(record, record.affectedPackages(), evidence);
                })
            .toList();
    MavenAssessmentFixtures.writeCacheRecords(prepared.cacheConfig().cacheDirectory(), updated);
  }

  /* default */ static void mutateCurrentCveRecord(
      final MavenCorroboratedSourceScenario.Prepared prepared) throws IOException {
    final Path currentRecord =
        prepared
            .cacheConfig()
            .cacheDirectory()
            .resolve("cvelistV5/cves/2025/12xxx/CVE-2025-12345.json");
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode currentJson = (ObjectNode) mapper.readTree(currentRecord.toFile());
    boolean changed = false;
    for (final JsonNode entry : currentJson.path("containers").path("cna").path("affected")) {
      for (final JsonNode version : entry.path("versions")) {
        if (version instanceof ObjectNode versionObject
            && "affected".equals(versionObject.path("status").asText())) {
          versionObject.put("status", "unaffected");
          changed = true;
        }
      }
    }
    if (!changed) {
      final boolean alreadyMutated =
          currentJson.path("containers").path("cna").path("affected").findValues("status").stream()
              .anyMatch(status -> "unaffected".equals(status.asText()));
      if (!alreadyMutated) {
        throw new IOException("CVE fixture did not contain an affected status to mutate");
      }
      return;
    }
    mapper.writeValue(currentRecord.toFile(), currentJson);
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
