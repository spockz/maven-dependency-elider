// WHY: Binds normalized bans to one isolated Resolver graph before Elide applies them.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.MavenAnalysisEvidence.RootEvidence;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.plugin.MojoFailureException;

/** Immutable ban decision for the effective inventory and optional original audit. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
record MavenBanPlan(
    String contextFingerprint,
    String resolverFingerprint,
    List<Entry> entries,
    MavenBanAuditContext auditContext,
    Map<ArtifactCoordinate, Set<String>> forcedAbsentClassProviders) {
  MavenBanPlan {
    entries = List.copyOf(entries);
    java.util.Objects.requireNonNull(auditContext, "auditContext");
    forcedAbsentClassProviders = immutableClassProviders(forcedAbsentClassProviders);
  }

  static MavenBanPlan empty() {
    return new MavenBanPlan("none", "none", List.of(), MavenBanAuditContext.empty(), Map.of());
  }

  static MavenBanPlan create(
      final MavenAnalysisResolutionContext context, final AnalysisOptions options)
      throws MojoFailureException {
    return create(context, options, null);
  }

  static MavenBanPlan create(
      final MavenAnalysisResolutionContext context,
      final AnalysisOptions options,
      final MavenOriginalInputAudit.Inventory originalAudit)
      throws MojoFailureException {
    final BanishedDependencyPolicy.Resolution resolution =
        BanishedDependencyPolicy.resolve(
            options.retainedArtifacts(),
            options.banishedDependencies(),
            context.project().getDependencies(),
            options.trim().passThroughArtifacts(),
            context.artifacts().resolvedSnapshots(),
            context.artifacts().directSnapshots());
    if (!resolution.requested().isEmpty()
        && context.provenance()
            == MavenAnalysisResolutionContext.Provenance.CAPTURED_EFFECTIVE_RESOLVER
        && originalAudit == null) {
      throw new MojoFailureException(
          "elide.banishedDependencies requires a complete original-input audit when the core "
              + "extension is active");
    }
    final BanishedDependencyOriginalAuditPolicy.Resolution originalResolution;
    final MavenBanAuditContext auditContext;
    if (originalAudit == null) {
      originalResolution = null;
      auditContext = MavenBanAuditContext.empty();
    } else {
      try {
        originalResolution =
            BanishedDependencyOriginalAuditPolicy.resolve(
                options.banishedDependencies(), originalAudit.resolvedArtifacts());
        validateOriginalEffectiveMatches(resolution, originalResolution);
        auditContext = MavenBanAuditContext.create(originalAudit, context);
      } catch (final IOException exception) {
        throw new MojoFailureException(
            "Cannot bind the original-input ban audit to the effective Resolver inventory: "
                + exception.getMessage(),
            exception);
      }
    }
    final List<Entry> entries =
        resolution.matches().stream().map(match -> entry(match, originalResolution)).toList();
    final String resolverFingerprint = context.graphPairFingerprint();
    final String contextFingerprint = contextFingerprint(resolverFingerprint, auditContext);
    return new MavenBanPlan(
        contextFingerprint, resolverFingerprint, entries, auditContext, Map.of());
  }

  static String contextFingerprint(
      final String resolverFingerprint, final MavenBanAuditContext auditContext) {
    return MavenElisionGraphBinding.sha256(
        List.of("maven-ban-context-v1", resolverFingerprint, auditContext.identityFingerprint()));
  }

  private static Map<ArtifactCoordinate, Set<String>> immutableClassProviders(
      final Map<ArtifactCoordinate, Set<String>> providers) {
    final Map<ArtifactCoordinate, Set<String>> immutable = new ConcurrentHashMap<>();
    providers.forEach((coordinate, classes) -> immutable.put(coordinate, Set.copyOf(classes)));
    return java.util.Collections.unmodifiableMap(immutable);
  }

  private static void validateOriginalEffectiveMatches(
      final BanishedDependencyPolicy.Resolution effective,
      final BanishedDependencyOriginalAuditPolicy.Resolution original)
      throws MojoFailureException {
    for (final BanishedDependencyPolicy.Match effectiveMatch : effective.matches()) {
      final BanishedDependencyOriginalAuditPolicy.Match originalMatch =
          original.matches().stream()
              .filter(match -> match.dependency().equals(effectiveMatch.dependency()))
              .findFirst()
              .orElseThrow(() -> missingOriginalBan(effectiveMatch.dependency()));
      if (!originalMatch.artifacts().isEmpty() && effectiveMatch.artifacts().isEmpty()) {
        continue;
      }
      if (originalMatch.artifacts().isEmpty() && !effectiveMatch.artifacts().isEmpty()) {
        throw new MojoFailureException(
            "Effective Resolver inventory contains a ban absent from the original audit: "
                + effectiveMatch.dependency());
      }
      final Set<EffectiveGraphDecisionIndex.Gavce> originalIdentities =
          originalMatch.artifacts().stream()
              .map(MavenOriginalInputAudit.AuditArtifact::coordinate)
              .map(EffectiveGraphDecisionIndex.Gavce::of)
              .collect(java.util.stream.Collectors.toSet());
      if (effectiveMatch.artifacts().stream()
          .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
          .map(EffectiveGraphDecisionIndex.Gavce::of)
          .anyMatch(identity -> !originalIdentities.contains(identity))) {
        throw new MojoFailureException(
            "Effective Resolver ban variants do not correspond to the original audit: "
                + effectiveMatch.dependency());
      }
    }
  }

  private static MojoFailureException missingOriginalBan(final BanishedDependency dependency) {
    return new MojoFailureException("Original-input audit omitted requested ban " + dependency);
  }

  private static Entry entry(
      final BanishedDependencyPolicy.Match match,
      final BanishedDependencyOriginalAuditPolicy.Resolution originalResolution) {
    final List<ArtifactCoordinate> effective =
        match.artifacts().stream()
            .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
            .sorted()
            .toList();
    final List<ArtifactCoordinate> original;
    if (originalResolution == null) {
      original = effective;
    } else {
      original =
          originalResolution.matches().stream()
              .filter(value -> value.dependency().equals(match.dependency()))
              .flatMap(value -> value.artifacts().stream())
              .map(MavenOriginalInputAudit.AuditArtifact::coordinate)
              .distinct()
              .sorted()
              .toList();
    }
    Entry.Status status = Entry.Status.EXCLUDED_BEFORE_RESOLUTION;
    if (effective.isEmpty() && original.isEmpty()) {
      status = Entry.Status.UNMATCHED;
    }
    if (!effective.isEmpty()) {
      status = Entry.Status.FORCED_ABSENT_AFTER_RESOLUTION;
    }
    return new Entry(match.dependency(), effective, original, status);
  }

  boolean requested() {
    return !entries.isEmpty();
  }

  Set<ArtifactCoordinate> forcedAbsentAfterResolution() {
    final Set<ArtifactCoordinate> coordinates = new TreeSet<>();
    entries.forEach(entry -> coordinates.addAll(entry.artifacts()));
    return Set.copyOf(coordinates);
  }

  void verifyContext(final MavenAnalysisResolutionContext context) throws MojoFailureException {
    if (requested() && !resolverFingerprint.equals(context.graphPairFingerprint())) {
      throw new MojoFailureException("Maven ban plan does not match its Resolver graph");
    }
  }

  void verifyCompleteness(final CompletenessOptions completeness) throws MojoFailureException {
    if (requiresAbsenceProof()
        && !completeness.sourceRootsComplete()
        && !completeness.productionClassesComplete()) {
      throw new MojoFailureException(
          "strict ban enforcement is not available: elide.banishedDependencies requires "
              + "complete source roots or complete production class output to establish "
              + "application reference closure");
    }
  }

  boolean requiresAbsenceProof() {
    return entries.stream().anyMatch(entry -> entry.status() != Entry.Status.UNMATCHED);
  }

  void verifyEvidence(final RootEvidence evidence) throws MojoFailureException {
    auditContext.verifyEvidence(evidence);
    if (!requested()) {
      return;
    }
    for (final ArtifactCoordinate coordinate : forcedAbsentAfterResolution()) {
      if (evidence.bytecodeScan().isPresent() && !evidence.bytecodeScan().get().complete()) {
        throw conflict(coordinate, "production bytecode evidence is incomplete");
      }
      if (evidence.dynamicRoots().resourceProvidersByDeclaringArtifact().entrySet().stream()
          .anyMatch(
              source ->
                  !source.getKey().equals(coordinate) && source.getValue().contains(coordinate))) {
        throw conflict(coordinate, "resource or provider metadata requires the artifact");
      }
    }
  }

  void verifyRetainedClosure(
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final ElisionDecision effectiveDecision,
      final TrimAnalysisResult trimAnalysis,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException, MojoFailureException {
    auditContext.verifyRetainedClosure(
        prepared, effectiveDecision, trimAnalysis, forcedUnchanged, forcedAbsentClassProviders);
  }

  MavenBanPlan withVerifiedEvidence(final RootEvidence evidence) throws MojoFailureException {
    verifyEvidence(evidence);
    final Map<ArtifactCoordinate, Set<String>> providers = new ConcurrentHashMap<>();
    for (final ArtifactCoordinate coordinate : forcedAbsentAfterResolution()) {
      final Set<String> classes = classNamesFor(coordinate, evidence);
      if (!classes.isEmpty()) {
        providers.put(coordinate, Set.copyOf(classes));
      }
    }
    return new MavenBanPlan(
        contextFingerprint, resolverFingerprint, entries, auditContext, providers);
  }

  private static Set<String> classNamesFor(
      final ArtifactCoordinate coordinate, final RootEvidence evidence) {
    final Set<String> classes = new TreeSet<>();
    evidence
        .index()
        .classesByArtifact()
        .forEach(
            (artifact, names) -> {
              if (artifact.coordinate().equals(coordinate)) {
                classes.addAll(names);
              }
            });
    return classes;
  }

  private static MojoFailureException conflict(
      final ArtifactCoordinate coordinate, final String reason) {
    return new MojoFailureException(
        "elide.banishedDependencies conflicts with " + coordinate + ": " + reason);
  }

  ElisionDecision forceAbsent(final ElisionDecision decision) throws MojoFailureException {
    if (!requested()) {
      return decision;
    }
    final Set<ArtifactCoordinate> retained = new LinkedHashSet<>(decision.retainedArtifacts());
    final Set<ArtifactCoordinate> elided = new LinkedHashSet<>(decision.elidedArtifacts());
    for (final ArtifactCoordinate coordinate : forcedAbsentAfterResolution()) {
      if (!retained.remove(coordinate) && !elided.contains(coordinate)) {
        throw conflict(coordinate, "resolved artifact is missing from the raw decision");
      }
      elided.add(coordinate);
    }
    return new ElisionDecision(
        retained,
        elided,
        decision.retainedClassesPerArtifact(),
        decision.unusedClassesPerArtifact(),
        decision.elapsedNanos());
  }

  void verifyGraph(final EffectiveGraphPolicy.Evaluation evaluation) throws MojoFailureException {
    if (!requested()) {
      return;
    }
    if (evaluation.failClosed()) {
      throw new MojoFailureException(
          "Maven ban cannot establish graph absence: " + evaluation.failClosedReason());
    }
    for (final ArtifactCoordinate coordinate : forcedAbsentAfterResolution()) {
      if (!evaluation.elidedArtifacts().contains(coordinate)) {
        throw conflict(coordinate, "Resolver graph protects or promotes the banned artifact");
      }
    }
  }

  void verifyNoPromotion(final Set<ArtifactCoordinate> newlyReached) throws MojoFailureException {
    for (final ArtifactCoordinate coordinate : forcedAbsentAfterResolution()) {
      if (newlyReached.contains(coordinate)) {
        throw conflict(coordinate, "retained bytecode, resources, or providers reach the artifact");
      }
    }
  }

  void verifyAuditFresh(
      final org.apache.maven.project.MavenProject project,
      final org.apache.maven.execution.MavenSession session)
      throws IOException {
    MavenBanAuditFreshnessVerifier.verify(auditContext, project, session);
  }

  void verifyAuditBytesFresh() throws IOException {
    auditContext.verifyArtifactBytes();
  }

  /** One normalized policy identity and its current resolved matches. */
  record Entry(
      BanishedDependency dependency,
      List<ArtifactCoordinate> artifacts,
      List<ArtifactCoordinate> originalArtifacts,
      Status status) {
    Entry {
      artifacts = List.copyOf(artifacts);
      originalArtifacts = List.copyOf(originalArtifacts);
      java.util.Objects.requireNonNull(status, "status");
    }

    boolean matched() {
      return status != Status.UNMATCHED;
    }

    /** Distinguishes policy absence from resolution and inventory misses. */
    /* package */ enum Status {
      UNMATCHED,
      EXCLUDED_BEFORE_RESOLUTION,
      FORCED_ABSENT_AFTER_RESOLUTION
    }
  }
}
