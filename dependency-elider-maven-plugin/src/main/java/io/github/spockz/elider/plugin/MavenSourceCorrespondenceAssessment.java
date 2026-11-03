// WHY: Provides structured omitted-code proof verification for Maven assessments.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.OmittedCodeProof;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.model.StructuredSourceProofRequest;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Verifies exact, raw-applicable structured claims against physical artifacts. */
final class MavenSourceCorrespondenceAssessment {
  /** Maven context for exact source lookup. */
  private final MavenProject project;

  /** Original session is copied before Maven resolves the source classifier. */
  private final MavenSession session;

  /** Resolver is absent for assessment paths without exact source lookup. */
  private final Optional<MavenSourceClassifierResolver> resolver;

  /** Path-root translation is a user assumption, never a completeness signal. */
  private final boolean conventionalLayoutAssumed;

  private MavenSourceCorrespondenceAssessment(
      final MavenProject project,
      final MavenSession session,
      final Optional<MavenSourceClassifierResolver> resolver,
      final boolean conventionalLayoutAssumed) {
    this.project = project;
    this.session = session;
    this.resolver = Objects.requireNonNull(resolver, "resolver");
    this.conventionalLayoutAssumed = conventionalLayoutAssumed;
  }

  /* default */ static MavenSourceCorrespondenceAssessment unavailable(
      final boolean conventionalLayoutAssumed) {
    return new MavenSourceCorrespondenceAssessment(
        null, null, Optional.empty(), conventionalLayoutAssumed);
  }

  /* default */ static MavenSourceCorrespondenceAssessment configured(
      final MavenProject project,
      final MavenSession session,
      final Optional<MavenSourceClassifierResolver> resolver,
      final boolean conventionalLayoutAssumed) {
    return new MavenSourceCorrespondenceAssessment(
        project, session, resolver, conventionalLayoutAssumed);
  }

  /* default */ boolean canResolve() {
    return resolver.isPresent() && project != null && session != null;
  }

  /* default */ VexAttestation proveStructured(
      final String osvId,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate,
      final CacheConfig cacheConfig,
      final ArtifactTrimRecord trimRecord)
      throws IOException {
    if (!canResolve() || cacheConfig.expectedProducer().isEmpty()) {
      throw new IOException(
          "Structured proof requires a configured source resolver and expected cache producer");
    }
    final MavenSourceClassifierResolver.ResolvedSourceArtifact sourceArtifact =
        resolver.orElseThrow().resolve(candidate, project, session);
    final StructuredSourceProofRequest request =
        new StructuredSourceProofRequest(
            osvId,
            evidence,
            candidate,
            cacheConfig.cacheDirectory().resolve("cvelistV5"),
            cacheConfig.cacheDirectory().resolve("index.json"),
            cacheConfig.expectedProducer().orElseThrow(),
            sourceArtifact.path(),
            sourceArtifact.coordinate(),
            sourceArtifact.repositoryProvenance(),
            conventionalLayoutAssumed);
    return OmittedCodeProof.proveStructured(request, trimRecord);
  }
}
