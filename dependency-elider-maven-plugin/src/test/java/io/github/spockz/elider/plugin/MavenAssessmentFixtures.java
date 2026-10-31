// WHY: Keeps typed cache fixture construction out of the assessment behavior tests.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveVersionClaim;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeWriter;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Shared constructors for immutable advisory assessment test fixtures. */
final class MavenAssessmentFixtures {
  /** Producer stamped on local typed-cache fixtures. */
  /* package */
  static final CacheProducerIdentity CACHE_PRODUCER =
      new CacheProducerIdentity("io.github.spockz", "dependency-elider", "1.0.0", null);

  /** Ecosystem value used by Maven package fixtures. */
  private static final String MAVEN_ECOSYSTEM = "Maven";

  /** Version range used by cache-only proof-admission fixtures. */
  private static final String TEST_VERSION_RANGE = "[1.0,2.0)";

  private MavenAssessmentFixtures() {
    // Static fixture methods only.
  }

  /* package */
  static byte[] cacheIndex(final ArtifactCoordinate coordinate, final String cveId)
      throws IOException {
    final AdvisoryScope scope =
        new AdvisoryScope(
            cveId,
            ArtifactCoordinate.of(coordinate.groupId(), coordinate.artifactId(), null),
            TEST_VERSION_RANGE,
            MAVEN_ECOSYSTEM,
            coordinate.groupId() + ":" + coordinate.artifactId());
    final StructuredSourceClassEvidence reviewEvidence =
        new StructuredSourceClassEvidence(
            scope,
            new AdvisoryProvenance(EvidenceOrigin.CVE_LIST, cveId, null, "a".repeat(64)),
            "containers.cna.affected[0]",
            "Example:" + coordinate.artifactId(),
            Set.of("src/main/java/org/example/Vulnerable.java"),
            Set.of(),
            Map.of("src/main/java/org/example/Vulnerable.java", Set.of("org.example.Vulnerable")),
            Map.of());
    final OsvAdvisoryRecord record =
        new OsvAdvisoryRecord(
            "GHSA-cache-only",
            Set.of(cveId),
            List.of(
                new OsvAffectedPackage(
                    MAVEN_ECOSYSTEM,
                    coordinate.groupId() + ":" + coordinate.artifactId(),
                    scope.affectedCoordinate(),
                    List.of(),
                    List.of())),
            List.of(
                new CveAffectedEntryContext(
                    "containers.cna.affected[0]",
                    "Example",
                    coordinate.artifactId(),
                    "pkg:maven/" + coordinate.groupId() + "/" + coordinate.artifactId(),
                    null,
                    null,
                    List.of(new CveVersionClaim("1.0", "affected", null, null, null, List.of())),
                    Set.of("src/main/java/org/example/Vulnerable.java"),
                    Set.of())),
            List.of(
                reviewEvidence,
                new HeuristicCandidateEvidence(
                    scope,
                    new AdvisoryProvenance(
                        EvidenceOrigin.REFERENCE_URL,
                        "GHSA-cache-only#reference:0",
                        URI.create("https://example.test/commit/source.java"),
                        "b".repeat(64)),
                    Set.of("org.example.Vulnerable"),
                    Set.of(coordinate.groupId() + ":" + coordinate.artifactId()))));
    return new VulnerabilityCacheEnvelopeWriter().encode(CACHE_PRODUCER, List.of(record));
  }

  /* package */
  static byte[] legacyCommitCache() throws IOException {
    final ArtifactCoordinate coordinate =
        ArtifactCoordinate.of("org.apache.httpcomponents", "httpclient", "4.3.4");
    final ArtifactCoordinate scopeCoordinate =
        ArtifactCoordinate.of(coordinate.groupId(), coordinate.artifactId(), null);
    final AdvisoryScope scope =
        new AdvisoryScope(
            "CVE-2014-3577",
            scopeCoordinate,
            "(,4.3.5)",
            "Maven",
            "org.apache.httpcomponents:httpclient");
    final HeuristicCandidateEvidence commitCandidate =
        new HeuristicCandidateEvidence(
            scope,
            new AdvisoryProvenance(
                EvidenceOrigin.REFERENCE_URL,
                "GHSA-transcript-httpclient#reference:0",
                URI.create(
                    "https://github.com/apache/httpcomponents-client/commit/"
                        + "51cc67567765d67f878f0dcef61b5ded454d3122"),
                "a".repeat(64)),
            Set.of("org.apache.http.conn.ssl.AbstractVerifier"),
            Set.of("org.apache.httpcomponents:httpclient"));
    final OsvAdvisoryRecord record =
        new OsvAdvisoryRecord(
            "GHSA-transcript-httpclient",
            Set.of("CVE-2014-3577"),
            List.of(
                new OsvAffectedPackage(
                    MAVEN_ECOSYSTEM,
                    "org.apache.httpcomponents:httpclient",
                    scopeCoordinate,
                    List.of(),
                    List.of())),
            List.of(),
            List.of(
                new PackageAdvisoryEvidence(
                    scope,
                    new AdvisoryProvenance(
                        EvidenceOrigin.OSV, "GHSA-transcript-httpclient", null, "a".repeat(64))),
                commitCandidate));
    return new VulnerabilityCacheEnvelopeWriter().encode(CACHE_PRODUCER, List.of(record));
  }

  /* package */
  static byte[] exactVersionDisjointRangeCache(final ArtifactCoordinate coordinate)
      throws IOException {
    final String osvId = "GHSA-exact-version";
    final String cveId = "CVE-2026-12345";
    final String packageName = coordinate.groupId() + ":" + coordinate.artifactId();
    final ArtifactCoordinate scopeCoordinate =
        ArtifactCoordinate.of(coordinate.groupId(), coordinate.artifactId(), null);
    final AdvisoryScope scope =
        new AdvisoryScope(cveId, scopeCoordinate, "[2.0,3.0)", MAVEN_ECOSYSTEM, packageName);
    final OsvAffectedPackage affectedPackage =
        new OsvAffectedPackage(
            MAVEN_ECOSYSTEM,
            packageName,
            scopeCoordinate,
            List.of(coordinate.version()),
            List.of(
                new OsvAffectedRange(
                    "ECOSYSTEM",
                    null,
                    List.of(Map.of("introduced", "2.0"), Map.of("fixed", "3.0")))));
    final OsvAdvisoryRecord record =
        new OsvAdvisoryRecord(
            osvId,
            Set.of(cveId),
            List.of(affectedPackage),
            List.of(),
            List.of(
                new PackageAdvisoryEvidence(
                    scope, new AdvisoryProvenance(EvidenceOrigin.OSV, osvId, null, "c".repeat(64))),
                new HeuristicCandidateEvidence(
                    scope,
                    new AdvisoryProvenance(
                        EvidenceOrigin.REFERENCE_URL,
                        osvId + "#reference:0",
                        URI.create("https://example.test/candidates"),
                        "d".repeat(64)),
                    Set.of("org.example.Candidate"),
                    Set.of(packageName))));
    return new VulnerabilityCacheEnvelopeWriter().encode(CACHE_PRODUCER, List.of(record));
  }

  /* package */
  static byte[] ambiguousSameStatusPackageOwnerCache(final ArtifactCoordinate coordinate)
      throws IOException {
    final String osvId = "GHSA-ambiguous-owner";
    final String cveId = "CVE-2026-12345";
    final String packageName = coordinate.groupId() + ":" + coordinate.artifactId();
    final ArtifactCoordinate scopeCoordinate =
        ArtifactCoordinate.of(coordinate.groupId(), coordinate.artifactId(), null);
    final AdvisoryScope scope =
        new AdvisoryScope(cveId, scopeCoordinate, "[2.0,3.0)", MAVEN_ECOSYSTEM, packageName);
    final OsvAffectedPackage exactVersion =
        new OsvAffectedPackage(
            MAVEN_ECOSYSTEM,
            packageName,
            scopeCoordinate,
            List.of(coordinate.version()),
            List.of());
    final OsvAffectedPackage exactVersionWithRange =
        new OsvAffectedPackage(
            MAVEN_ECOSYSTEM,
            packageName,
            scopeCoordinate,
            List.of(coordinate.version()),
            List.of(
                new OsvAffectedRange(
                    "ECOSYSTEM",
                    null,
                    List.of(Map.of("introduced", "2.0"), Map.of("fixed", "3.0")))));
    final OsvAdvisoryRecord record =
        new OsvAdvisoryRecord(
            osvId,
            Set.of(cveId),
            List.of(exactVersion, exactVersionWithRange),
            List.of(),
            List.of(
                new PackageAdvisoryEvidence(
                    scope, new AdvisoryProvenance(EvidenceOrigin.OSV, osvId, null, "c".repeat(64))),
                new HeuristicCandidateEvidence(
                    scope,
                    new AdvisoryProvenance(
                        EvidenceOrigin.REFERENCE_URL,
                        osvId + "#reference:0",
                        URI.create("https://example.test/candidates"),
                        "d".repeat(64)),
                    Set.of("org.example.Candidate"),
                    Set.of(packageName))));
    return new VulnerabilityCacheEnvelopeWriter().encode(CACHE_PRODUCER, List.of(record));
  }
}
