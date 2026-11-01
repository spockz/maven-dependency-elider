/* WHY: Rebinds source evidence to current CNA and OSV bytes. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.scanner.CveSourceRecordReader;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelope;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.Locale;

/** Validates untrusted structured-proof inputs before source reproduction begins. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class LiveStructuredSourceValidator {
  /** Expected cardinality for source-owner and product selection. */
  private static final int ONE_MATCH = 1;

  private LiveStructuredSourceValidator() {}

  /** Rebinds the request to the current typed owner and raw CNA source record. */
  static ObservedInputs observe(final StructuredSourceProofRequest request) throws IOException {
    final OsvAdvisoryRecord owner = currentOwner(request);
    final StructuredSourceClassEvidence evidence = request.sourceEvidence();
    final ArtifactCoordinate candidate = request.candidate();
    requireExactEvidenceOwner(owner, evidence, candidate);
    final String cveId = evidence.scope().cveId();
    final CveSourceRecordReader.ObservedSource current =
        CveSourceRecordReader.read(request.cveListGitDir(), cveId);
    requireCurrentSource(owner, evidence, current, cveId);
    final CveAffectedEntryContext currentEntry = uniqueCurrentEntry(current, evidence, candidate);
    final CveAffectedEntryContext cachedEntry = uniqueCachedEntry(owner, evidence);
    requireEntryUnchanged(cachedEntry, currentEntry, evidence, candidate);
    final OsvAffectedPackage affectedPackage = uniqueOsvPackage(owner, evidence, candidate);
    return new ObservedInputs(owner, evidence, candidate, current, currentEntry, affectedPackage);
  }

  private static OsvAdvisoryRecord currentOwner(final StructuredSourceProofRequest request)
      throws IOException {
    final VulnerabilityCacheEnvelope envelope;
    try (InputStream input = Files.newInputStream(request.advisoryIndex())) {
      envelope = new VulnerabilityCacheEnvelopeReader().read(input, request.expectedProducer());
    }
    final List<OsvAdvisoryRecord> records =
        envelope.records().stream()
            .filter(record -> record.osvId().equals(request.osvId()))
            .toList();
    if (records.size() != ONE_MATCH) {
      throw new IOException("Current typed advisory index has no unique OSV owner");
    }
    return records.getFirst();
  }

  private static void requireExactEvidenceOwner(
      final OsvAdvisoryRecord owner,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate)
      throws IOException {
    if (evidence.provenance().origin() != EvidenceOrigin.CVE_LIST
        || evidence.scope().cveId() == null
        || !evidence.provenance().sourceRecordId().equals(evidence.scope().cveId())
        || (!evidence.scope().cveId().equals(owner.osvId())
            && !owner.aliases().contains(evidence.scope().cveId()))
        || owner.evidence().stream().filter(evidence::equals).count() != ONE_MATCH
        || !sameScopeComponent(evidence.scope().affectedCoordinate(), candidate)) {
      throw new IOException(
          "Structured source evidence is not bound to this exact owner candidate");
    }
  }

  private static void requireCurrentSource(
      final OsvAdvisoryRecord owner,
      final StructuredSourceClassEvidence evidence,
      final CveSourceRecordReader.ObservedSource current,
      final String cveId)
      throws IOException {
    if (!current.sourceRecordSha256().equals(evidence.provenance().sourceRecordSha256())
        || !current.sourceRecordSha256().equals(current.metadata().sourceRecordSha256())
        || !current.metadata().authorizesStructuredClaims(cveId, owner.osvId(), owner.aliases())) {
      throw new IOException("Current CVE source bytes no longer authorize this structured claim");
    }
  }

  private static CveAffectedEntryContext uniqueCurrentEntry(
      final CveSourceRecordReader.ObservedSource current,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate)
      throws IOException {
    final List<CveAffectedEntryContext> matches =
        current.affectedEntries().stream()
            .filter(entry -> entry.entryIdentity().equals(evidence.cnaAffectedEntryIdentity()))
            .toList();
    final long matchingProducts =
        current.affectedEntries().stream()
            .filter(entry -> MavenPackageIdentity.matchesCnaArtifact(entry, candidate))
            .count();
    if (matches.size() != ONE_MATCH || matchingProducts != ONE_MATCH) {
      throw new IOException("Current CVE source has no unique matching affected entry");
    }
    return matches.getFirst();
  }

  private static CveAffectedEntryContext uniqueCachedEntry(
      final OsvAdvisoryRecord owner, final StructuredSourceClassEvidence evidence)
      throws IOException {
    final List<CveAffectedEntryContext> matches =
        owner.cnaAffectedEntries().stream()
            .filter(entry -> entry.entryIdentity().equals(evidence.cnaAffectedEntryIdentity()))
            .toList();
    if (matches.size() != ONE_MATCH) {
      throw new IOException("Cached OSV owner has no unique matching CNA entry");
    }
    return matches.getFirst();
  }

  private static void requireEntryUnchanged(
      final CveAffectedEntryContext cached,
      final CveAffectedEntryContext current,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate)
      throws IOException {
    final String product =
        (current.vendor() == null ? "" : current.vendor()) + ":" + current.product();
    if (!cached.equals(current)
        || !current.programFiles().equals(evidence.programFiles())
        || !current.programRoutines().equals(evidence.programRoutines())
        || !product.equals(evidence.affectedProductIdentity())
        || !MavenPackageIdentity.matchesCnaArtifact(current, candidate)) {
      throw new IOException("Current CNA product or source claims differ from the assessed record");
    }
  }

  private static OsvAffectedPackage uniqueOsvPackage(
      final OsvAdvisoryRecord owner,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate)
      throws IOException {
    final List<OsvAffectedPackage> matches =
        owner.affectedPackages().stream()
            .filter(
                item ->
                    isMaven(item.ecosystem())
                        && item.packageName()
                            .equals(candidate.groupId() + ":" + candidate.artifactId())
                        && item.ecosystem().equals(evidence.scope().ecosystem())
                        && item.packageName().equals(evidence.scope().packageName())
                        && "jar".equals(candidate.type())
                        && candidate.classifier().isEmpty())
            .toList();
    if (matches.size() != ONE_MATCH) {
      throw new IOException("Current OSV owner has no unique exact Maven package claim");
    }
    return matches.getFirst();
  }

  private static boolean isMaven(final String ecosystem) {
    return "Maven".equalsIgnoreCase(ecosystem)
        || ecosystem.toLowerCase(Locale.ROOT).startsWith("maven:");
  }

  private static boolean sameScopeComponent(
      final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return isConcreteVersion(right.version())
        && (left.version() == null || left.version().equals(right.version()))
        && left.groupId().equals(right.groupId())
        && left.artifactId().equals(right.artifactId())
        && left.type().equals(right.type())
        && left.classifier().equals(right.classifier());
  }

  private static boolean isConcreteVersion(final String version) {
    return version != null && !version.isBlank();
  }

  /** Holds observations only; it grants no proof authority. */
  record ObservedInputs(
      OsvAdvisoryRecord owner,
      StructuredSourceClassEvidence evidence,
      ArtifactCoordinate candidate,
      CveSourceRecordReader.ObservedSource currentCveRecord,
      CveAffectedEntryContext cnaEntry,
      OsvAffectedPackage osvPackage) {}
}
