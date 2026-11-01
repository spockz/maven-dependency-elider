// WHY: Keeps structured omitted-code admission separate from POM mapping assessment.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.AdvisoryEvidence;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.MavenPackageIdentity;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import org.apache.maven.plugin.logging.Log;

/** Selects unambiguous claims and asks core to verify omitted-code proof. */
final class MavenStructuredProofAssessment {
  /** Exact count required for one source-claim owner. */
  private static final int SINGLE_OWNER_COUNT = 1;

  /** Source resolver and core proof entry point for this assessment. */
  private final MavenSourceCorrespondenceAssessment sourceAssessment;

  /** Maven logger for observable proof refusals. */
  private final Log log;

  /* default */ MavenStructuredProofAssessment(
      final MavenSourceCorrespondenceAssessment sourceAssessment, final Log log) {
    this.sourceAssessment = sourceAssessment;
    this.log = log;
  }

  /* default */ List<VexAttestation> proveCandidate(
      final CacheConfig cacheConfig,
      final List<OsvAdvisoryRecord> records,
      final List<VulnerabilitySymbolMapping> pomMappings,
      final ArtifactCoordinate candidate,
      final ArtifactTrimRecord trimRecord,
      final Set<String> existingAttestations) {
    final Set<String> pomOverrides = applicablePomCves(pomMappings, candidate);
    final Map<String, List<StructuredProofCandidate>> byCve = candidatesByCve(records, candidate);
    final List<VexAttestation> proofs = new ArrayList<>();
    for (final Map.Entry<String, List<StructuredProofCandidate>> entry : byCve.entrySet()) {
      if (entry.getValue().size() != SINGLE_OWNER_COUNT) {
        debugAbstention(entry.getKey(), "multiple OSV/CNA claim owners match this component");
        continue;
      }
      if (existingAttestations.contains(entry.getKey()) || pomOverrides.contains(entry.getKey())) {
        continue;
      }
      final StructuredProofCandidate selected = entry.getValue().getFirst();
      try {
        proofs.add(
            sourceAssessment.proveStructured(
                selected.owner().osvId(), selected.evidence(), candidate, cacheConfig, trimRecord));
      } catch (final IOException | IllegalArgumentException | SecurityException failure) {
        debugAbstention(entry.getKey(), failure.getMessage());
      }
    }
    return List.copyOf(proofs);
  }

  private static Set<String> applicablePomCves(
      final List<VulnerabilitySymbolMapping> mappings, final ArtifactCoordinate candidate) {
    return MavenMappingApplicability.applicableMappings(
            mappings, candidate, MavenVulnerabilityAssessment.MAPPING_ORDER)
        .stream()
        .map(VulnerabilitySymbolMapping::cveId)
        .collect(Collectors.toSet());
  }

  @SuppressWarnings({
    "PMD.UseConcurrentHashMap", // Candidate groups are confined to this assessment call.
    "PMD.AvoidInstantiatingObjectsInLoops" // One value object is required for each source row.
  })
  private static Map<String, List<StructuredProofCandidate>> candidatesByCve(
      final List<OsvAdvisoryRecord> records, final ArtifactCoordinate candidate) {
    final Map<String, List<StructuredProofCandidate>> byCve = new TreeMap<>();
    for (final OsvAdvisoryRecord owner : records) {
      for (final AdvisoryEvidence evidence : owner.evidence()) {
        if (evidence instanceof StructuredSourceClassEvidence structured
            && structured.scope().cveId() != null
            && matchesCandidate(owner, structured, candidate)) {
          byCve
              .computeIfAbsent(structured.scope().cveId(), ignored -> new ArrayList<>())
              .add(new StructuredProofCandidate(owner, structured));
        }
      }
    }
    return byCve;
  }

  private static boolean matchesCandidate(
      final OsvAdvisoryRecord owner,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate) {
    final ArtifactCoordinate scope = evidence.scope().affectedCoordinate();
    if (!scope.groupId().equals(candidate.groupId())
        || !scope.artifactId().equals(candidate.artifactId())
        || !scope.type().equals(candidate.type())
        || !scope.classifier().equals(candidate.classifier())
        || (scope.version() != null && !scope.version().equals(candidate.version()))) {
      return false;
    }
    return owner.cnaAffectedEntries().stream()
        .filter(entry -> entry.entryIdentity().equals(evidence.cnaAffectedEntryIdentity()))
        .anyMatch(entry -> MavenPackageIdentity.matchesCnaArtifact(entry, candidate));
  }

  private void debugAbstention(final String cveId, final String reason) {
    if (log.isDebugEnabled()) {
      log.debug("Structured omitted-code proof abstained for " + cveId + ": " + reason);
    }
  }

  private record StructuredProofCandidate(
      OsvAdvisoryRecord owner, StructuredSourceClassEvidence evidence) {}
}
