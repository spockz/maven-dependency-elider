/* WHY: Isolates live source and advisory revalidation from explicit POM proof handling. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.applicability.MavenRawScopeApplicability;
import io.github.spockz.elider.correspondence.SourceReproductionEngine;
import io.github.spockz.elider.correspondence.SourceReproductionRequest;
import io.github.spockz.elider.correspondence.SourceReproductionResult;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.Objects;
import java.util.Set;

/** Revalidates current structured claims before the shared physical omission check. */
final class StructuredOmittedCodeProof {
  private StructuredOmittedCodeProof() {}

  /* default */ static VexAttestation prove(
      final StructuredSourceProofRequest request,
      final ArtifactTrimRecord trimRecord,
      final SourceReproductionEngine reproductionEngine)
      throws IOException {
    Objects.requireNonNull(request, "request");
    Objects.requireNonNull(trimRecord, "trimRecord");
    Objects.requireNonNull(reproductionEngine, "reproductionEngine");
    requireStructuredCandidate(request, trimRecord);
    final LiveStructuredSourceValidator.ObservedInputs before =
        LiveStructuredSourceValidator.observe(request);
    requireAffected(before);
    final SourceReproductionResult reproduction =
        reproduce(request, trimRecord, before, reproductionEngine);
    if (reproduction instanceof SourceReproductionResult.Abstained abstained) {
      throw new IOException(abstained.rationale());
    }
    final SourceReproductionResult.Completed completed =
        (SourceReproductionResult.Completed) reproduction;
    requireReproductionIdentity(request, trimRecord, completed);
    final StructuredClaimClassResolver.Result selection =
        StructuredClaimClassResolver.derive(before.cnaEntry(), completed);
    requireStable(before, LiveStructuredSourceValidator.observe(request));
    final StructuredProofProvenance provenance =
        provenance(before, completed, request.conventionalLayoutAssumed(), selection);
    final VexAttestation attestation =
        provePhysicalOmission(
            new VerifiedStructuredEvidence(
                request.sourceEvidence().scope().cveId(), selection.classNames(), provenance),
            trimRecord,
            reproductionEngine);
    verifyFinalInputs(request, trimRecord, completed, before);
    return attestation;
  }

  private static StructuredProofProvenance provenance(
      final LiveStructuredSourceValidator.ObservedInputs observed,
      final SourceReproductionResult.Completed completed,
      final boolean conventionalLayoutAssumed,
      final StructuredClaimClassResolver.Result selection) {
    return new StructuredProofProvenance(
        observed.owner().osvId(),
        observed.currentCveRecord().sourceRecordSha256(),
        observed.cnaEntry().entryIdentity(),
        observed.evidence().affectedProductIdentity(),
        StructuredProofProvenance.OsvSourceAuthority.CONFIGURED_PRODUCER_COMPATIBLE_INDEX,
        completed.sourcesCoordinate(),
        completed.sourcesArchiveSha256(),
        completed.sourceRepositoryProvenance(),
        completed.compilerIdentity(),
        completed.compilerOptions(),
        conventionalLayoutAssumed,
        rawScopeEvidence(observed),
        selection.attributions());
  }

  private static void requireStructuredCandidate(
      final StructuredSourceProofRequest request, final ArtifactTrimRecord trimRecord)
      throws IOException {
    if (!PhysicalOmissionChecks.sameArtifactIdentity(request.candidate(), trimRecord.coordinate())
        || request.candidate().version() == null
        || request.candidate().version().isBlank()
        || !"not_multi_release".equals(trimRecord.mrjarStatus())) {
      throw new IOException("Structured proof requires one exact ordinary trimmed artifact");
    }
  }

  private static void requireAffected(final LiveStructuredSourceValidator.ObservedInputs observed)
      throws IOException {
    final MavenRawScopeApplicability.Result applicability =
        MavenRawScopeApplicability.evaluateStructured(
            observed.osvPackage(), observed.cnaEntry(), observed.candidate().version());
    if (applicability.status() != MavenRawScopeApplicability.Status.AFFECTED) {
      throw new IOException(
          "Current raw OSV and CNA scope does not establish AFFECTED: "
              + applicability.rationale());
    }
  }

  private static SourceReproductionResult reproduce(
      final StructuredSourceProofRequest request,
      final ArtifactTrimRecord trimRecord,
      final LiveStructuredSourceValidator.ObservedInputs observed,
      final SourceReproductionEngine reproductionEngine) {
    final SourceReproductionRequest reproductionRequest =
        new SourceReproductionRequest(
            request.candidate(),
            request.sourcesCoordinate(),
            trimRecord.originalPath(),
            request.sourcesJar(),
            request.sourceRepositoryProvenance(),
            observed.cnaEntry().programFiles().stream().sorted().toList(),
            observed.cnaEntry().programRoutines().stream().sorted().toList(),
            request.conventionalLayoutAssumed());
    return reproductionEngine.reproduce(reproductionRequest);
  }

  private static void requireReproductionIdentity(
      final StructuredSourceProofRequest request,
      final ArtifactTrimRecord trimRecord,
      final SourceReproductionResult.Completed completed)
      throws IOException {
    if (!PhysicalOmissionChecks.sameArtifactIdentity(request.candidate(), completed.candidate())
        || !PhysicalOmissionChecks.sameArtifactIdentity(
            trimRecord.coordinate(), completed.candidate())
        || !request.sourcesCoordinate().equals(completed.sourcesCoordinate())
        || !trimRecord.originalSha256().equals(completed.originalArchiveSha256())) {
      throw new IOException("Source reproduction does not match the exact trim candidate");
    }
  }

  private static StructuredProofProvenance.RawScopeEvidence rawScopeEvidence(
      final LiveStructuredSourceValidator.ObservedInputs observed) {
    final MavenRawScopeApplicability.Result osv =
        MavenRawScopeApplicability.evaluateOsv(
            observed.osvPackage(), observed.candidate().version());
    final MavenRawScopeApplicability.Result cna =
        MavenRawScopeApplicability.evaluateCna(observed.cnaEntry(), observed.candidate().version());
    return new StructuredProofProvenance.RawScopeEvidence(
        observed.owner().modified(),
        observed.osvPackage().ecosystem(),
        observed.osvPackage().packageName(),
        observed.osvPackage().versions(),
        observed.osvPackage().ranges(),
        observed.cnaEntry().sourceRecord().state(),
        observed.cnaEntry().defaultStatus(),
        observed.cnaEntry().versions(),
        osv.status().name(),
        cna.status().name(),
        osv.rationale(),
        cna.rationale());
  }

  private static void requireStable(
      final LiveStructuredSourceValidator.ObservedInputs before,
      final LiveStructuredSourceValidator.ObservedInputs after)
      throws IOException {
    if (!before.owner().equals(after.owner())
        || !before.evidence().equals(after.evidence())
        || !before.candidate().equals(after.candidate())
        || !before
            .currentCveRecord()
            .sourceRecordSha256()
            .equals(after.currentCveRecord().sourceRecordSha256())
        || !before.cnaEntry().equals(after.cnaEntry())
        || !before.osvPackage().equals(after.osvPackage())) {
      throw new IOException("OSV or CNA source inputs changed during structured proof");
    }
  }

  private static void verifyFinalInputs(
      final StructuredSourceProofRequest request,
      final ArtifactTrimRecord trimRecord,
      final SourceReproductionResult.Completed completed,
      final LiveStructuredSourceValidator.ObservedInputs before)
      throws IOException {
    if (!completed
        .sourcesArchiveSha256()
        .equals(ArtifactDigests.read(request.sourcesJar()).sha256())) {
      throw new IOException("Sources archive changed during structured omission proof");
    }
    final ArtifactDigests original =
        PhysicalOmissionChecks.verifyDigest(
            trimRecord.originalPath(), trimRecord.originalSha256(), trimRecord.originalSha1());
    final ArtifactDigests trimmed =
        PhysicalOmissionChecks.verifyDigest(
            trimRecord.trimmedPath(), trimRecord.trimmedSha256(), trimRecord.trimmedSha1());
    if (!original.sha256().equals(completed.originalArchiveSha256())) {
      throw new IOException("Original archive changed during structured omission proof");
    }
    PhysicalOmissionChecks.verifyUnchanged(trimRecord, original, trimmed);
    requireStable(before, LiveStructuredSourceValidator.observe(request));
  }

  private static VexAttestation provePhysicalOmission(
      final VerifiedStructuredEvidence capability,
      final ArtifactTrimRecord trimRecord,
      final SourceReproductionEngine reproductionEngine)
      throws IOException {
    final ArtifactDigests original =
        PhysicalOmissionChecks.verifyDigest(
            trimRecord.originalPath(), trimRecord.originalSha256(), trimRecord.originalSha1());
    final ArtifactDigests trimmed =
        PhysicalOmissionChecks.verifyDigest(
            trimRecord.trimmedPath(), trimRecord.trimmedSha256(), trimRecord.trimmedSha1());
    final Set<String> originalClasses =
        reproductionEngine.readPhysicalClassInventory(
            trimRecord.coordinate(), trimRecord.originalPath(), trimRecord.originalSha256());
    final Set<String> trimmedClasses =
        reproductionEngine.readPhysicalClassInventory(
            trimRecord.coordinate(), trimRecord.trimmedPath(), trimRecord.trimmedSha256());
    final Set<String> absent =
        PhysicalOmissionChecks.verifySymbols(
            capability.vulnerableClasses(), originalClasses, trimmedClasses);
    PhysicalOmissionChecks.verifyUnchanged(trimRecord, original, trimmed);
    return VexAttestation.structuredOmittedCode(
        capability.cveId(),
        trimRecord.coordinate(),
        "CNA-declared source claims were rebound to current CVE and OSV inputs, reproduced "
            + "against the exact original archive, and their class families are absent from the "
            + "trimmed artifact. This establishes absence for those reproduced classes only; it "
            + "does not validate the CNA declaration's correctness or completeness.",
        absent,
        original.sha256(),
        trimmed.sha256(),
        capability.provenance());
  }

  private record VerifiedStructuredEvidence(
      String cveId, Set<String> vulnerableClasses, StructuredProofProvenance provenance) {
    private VerifiedStructuredEvidence {
      Objects.requireNonNull(cveId, "cveId");
      vulnerableClasses = Set.copyOf(vulnerableClasses);
      Objects.requireNonNull(provenance, "provenance");
    }
  }
}
