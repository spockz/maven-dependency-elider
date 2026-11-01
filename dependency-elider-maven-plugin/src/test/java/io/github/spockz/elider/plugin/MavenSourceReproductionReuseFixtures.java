// WHY: Builds a second exact CVE owner with the same bytes for multi-advisory reuse tests.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveSourceRecordMetadata;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.MavenPackageIdentity;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeReader;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** Installs independent CVE owners for source reuse tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenSourceReproductionReuseFixtures {
  /** Second CVE used by the reuse fixture. */
  static final String SECOND_CVE_ID = "CVE-2025-54321";

  /** Second OSV owner remains independent from the existing GHSA fixture record. */
  private static final String SECOND_OSV_ID = "GHSA-source-second";

  /** JSON object used to create the second exact source record. */
  private static final ObjectMapper JSON = new ObjectMapper();

  private MavenSourceReproductionReuseFixtures() {}

  /** Adds a second CVE record and typed OSV row. */
  static void installSecondCveOwner(final MavenCorroboratedSourceScenario.Prepared prepared)
      throws IOException {
    final Path cacheDirectory = prepared.cacheConfig().cacheDirectory();
    final OsvAdvisoryRecord firstOwner = readOwner(cacheDirectory.resolve("index.json"));
    final StructuredSourceClassEvidence firstEvidence = structuredEvidence(firstOwner);
    final Path secondCveRecord = writeSecondCveRecord(prepared.cveRecord(), cacheDirectory);
    final String secondDigest = ArtifactDigests.read(secondCveRecord).sha256();
    final List<CveAffectedEntryContext> secondEntries =
        firstOwner.cnaAffectedEntries().stream()
            .map(entry -> withSourceRecord(entry, secondDigest))
            .toList();
    final CveAffectedEntryContext selectedEntry =
        secondEntries.stream()
            .filter(entry -> entry.entryIdentity().equals(firstEvidence.cnaAffectedEntryIdentity()))
            .findFirst()
            .orElseThrow();
    final AdvisoryScope secondScope =
        new AdvisoryScope(
            SECOND_CVE_ID,
            firstEvidence.scope().affectedCoordinate(),
            firstEvidence.scope().versionRangeSpec(),
            firstEvidence.scope().ecosystem(),
            firstEvidence.scope().packageName());
    final StructuredSourceClassEvidence secondEvidence =
        new StructuredSourceClassEvidence(
            secondScope,
            new AdvisoryProvenance(EvidenceOrigin.CVE_LIST, SECOND_CVE_ID, null, secondDigest),
            selectedEntry.entryIdentity(),
            firstEvidence.affectedProductIdentity(),
            selectedEntry.programFiles(),
            selectedEntry.programRoutines(),
            firstEvidence.fileClassAttribution(),
            firstEvidence.routineClassAttribution());
    final OsvAdvisoryRecord secondOwner =
        new OsvAdvisoryRecord(
            SECOND_OSV_ID,
            firstOwner.modified(),
            Set.of(SECOND_CVE_ID),
            firstOwner.affectedPackages(),
            secondEntries,
            List.of(secondEvidence));
    MavenAssessmentFixtures.writeCacheRecords(cacheDirectory, List.of(firstOwner, secondOwner));
  }

  /** Installs a proof owner on another artifact plus a package-only review candidate. */
  static void installTwoArtifactOwners(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final ArtifactCoordinate secondCoordinate,
      final ArtifactCoordinate reviewCoordinate)
      throws IOException {
    final Path cacheDirectory = prepared.cacheConfig().cacheDirectory();
    final OsvAdvisoryRecord firstOwner = readOwner(cacheDirectory.resolve("index.json"));
    final StructuredSourceClassEvidence firstEvidence = structuredEvidence(firstOwner);
    final Path secondCveRecord = writeSecondCveRecord(prepared.cveRecord(), cacheDirectory);
    updateProductIdentity(secondCveRecord, secondCoordinate);
    final String secondDigest = ArtifactDigests.read(secondCveRecord).sha256();
    final List<CveAffectedEntryContext> secondEntries =
        firstOwner.cnaAffectedEntries().stream()
            .map(
                entry ->
                    withSecondProduct(
                        entry,
                        firstEvidence.cnaAffectedEntryIdentity(),
                        secondCoordinate,
                        secondDigest))
            .toList();
    final CveAffectedEntryContext selectedEntry =
        secondEntries.stream()
            .filter(entry -> entry.entryIdentity().equals(firstEvidence.cnaAffectedEntryIdentity()))
            .findFirst()
            .orElseThrow();
    if (!MavenPackageIdentity.matchesCnaScope(selectedEntry, secondCoordinate)) {
      throw new IllegalStateException("Second CNA product identity does not match its coordinate");
    }
    final StructuredSourceClassEvidence secondEvidence =
        new StructuredSourceClassEvidence(
            new AdvisoryScope(
                SECOND_CVE_ID,
                secondCoordinate,
                firstEvidence.scope().versionRangeSpec(),
                firstEvidence.scope().ecosystem(),
                secondCoordinate.toShortKey()),
            new AdvisoryProvenance(EvidenceOrigin.CVE_LIST, SECOND_CVE_ID, null, secondDigest),
            selectedEntry.entryIdentity(),
            selectedEntry.vendor() + ":" + selectedEntry.product(),
            selectedEntry.programFiles(),
            selectedEntry.programRoutines(),
            firstEvidence.fileClassAttribution(),
            firstEvidence.routineClassAttribution());
    final OsvAdvisoryRecord secondOwner =
        new OsvAdvisoryRecord(
            SECOND_OSV_ID,
            firstOwner.modified(),
            Set.of(SECOND_CVE_ID),
            List.of(packageFor(secondCoordinate, firstOwner.affectedPackages().getFirst())),
            secondEntries,
            List.of(secondEvidence));
    final OsvAdvisoryRecord reviewOwner =
        new OsvAdvisoryRecord(
            "GHSA-review-middle",
            firstOwner.modified(),
            Set.of(),
            List.of(packageFor(reviewCoordinate, firstOwner.affectedPackages().getFirst())),
            List.of(),
            List.of());
    MavenAssessmentFixtures.writeCacheRecords(
        cacheDirectory, List.of(firstOwner, reviewOwner, secondOwner));
  }

  private static OsvAdvisoryRecord readOwner(final Path index) throws IOException {
    try (InputStream input = Files.newInputStream(index)) {
      return new VulnerabilityCacheEnvelopeReader()
          .read(input, MavenAssessmentFixtures.CACHE_PRODUCER)
          .records()
          .getFirst();
    }
  }

  private static StructuredSourceClassEvidence structuredEvidence(final OsvAdvisoryRecord owner) {
    return owner.evidence().stream()
        .filter(StructuredSourceClassEvidence.class::isInstance)
        .map(StructuredSourceClassEvidence.class::cast)
        .findFirst()
        .orElseThrow();
  }

  private static Path writeSecondCveRecord(final Path sourceRecord, final Path cacheDirectory)
      throws IOException {
    final ObjectNode record = (ObjectNode) JSON.readTree(sourceRecord.toFile());
    ((ObjectNode) record.get("cveMetadata")).put("cveId", SECOND_CVE_ID);
    final Path target =
        cacheDirectory.resolve("cvelistV5/cves/2025/54xxx/").resolve(SECOND_CVE_ID + ".json");
    Files.createDirectories(target.getParent());
    JSON.writeValue(target.toFile(), record);
    return target;
  }

  private static CveAffectedEntryContext withSourceRecord(
      final CveAffectedEntryContext entry, final String sourceDigest) {
    return new CveAffectedEntryContext(
        entry.entryIdentity(),
        new CveSourceRecordMetadata(
            true, true, true, SECOND_CVE_ID, true, "PUBLISHED", sourceDigest),
        entry.vendor(),
        entry.product(),
        entry.packageUrl(),
        entry.collectionUrl(),
        entry.packageName(),
        entry.defaultStatus(),
        entry.versions(),
        entry.programFiles(),
        entry.programRoutines());
  }

  private static void updateProductIdentity(
      final Path sourceRecord, final ArtifactCoordinate coordinate) throws IOException {
    final ObjectNode record = (ObjectNode) JSON.readTree(sourceRecord.toFile());
    final ObjectNode cna = (ObjectNode) record.get("containers").get("cna");
    final ObjectNode affected = (ObjectNode) cna.withArray("affected").get(0);
    affected.put("product", coordinate.artifactId());
    affected.put("packageURL", packageUrl(coordinate));
    JSON.writeValue(sourceRecord.toFile(), record);
  }

  private static CveAffectedEntryContext withSecondProduct(
      final CveAffectedEntryContext entry,
      final String selectedEntryIdentity,
      final ArtifactCoordinate coordinate,
      final String sourceDigest) {
    final boolean selected = entry.entryIdentity().equals(selectedEntryIdentity);
    return new CveAffectedEntryContext(
        entry.entryIdentity(),
        new CveSourceRecordMetadata(
            true, true, true, SECOND_CVE_ID, true, "PUBLISHED", sourceDigest),
        entry.vendor(),
        selected ? coordinate.artifactId() : entry.product(),
        selected ? packageUrl(coordinate) : entry.packageUrl(),
        entry.collectionUrl(),
        entry.packageName(),
        entry.defaultStatus(),
        entry.versions(),
        entry.programFiles(),
        entry.programRoutines());
  }

  private static OsvAffectedPackage packageFor(
      final ArtifactCoordinate coordinate, final OsvAffectedPackage template) {
    return new OsvAffectedPackage(
        template.ecosystem(),
        coordinate.toShortKey(),
        new ArtifactCoordinate(
            coordinate.groupId(), coordinate.artifactId(), null, "jar", "", "compile"),
        List.of(coordinate.version()),
        template.ranges());
  }

  private static String packageUrl(final ArtifactCoordinate coordinate) {
    return "pkg:maven/" + coordinate.groupId() + "/" + coordinate.artifactId();
  }
}
