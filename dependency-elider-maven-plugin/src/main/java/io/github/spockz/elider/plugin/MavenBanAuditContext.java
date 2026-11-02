// WHY: Keeps original-only providers available for read-only closure checks without adding them
// to Maven's effective inventory or graph.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.plugin.MojoFailureException;

/** Read-only original resolver evidence for audit-only providers. */
record MavenBanAuditContext(
    MavenOriginalInputAudit.Inventory inventory,
    List<MavenOriginalInputAudit.AuditArtifact> auditOnlyArtifacts,
    ArtifactClassIndex auditOnlyClassIndex) {
  MavenBanAuditContext {
    auditOnlyArtifacts = List.copyOf(auditOnlyArtifacts);
  }

  /* package */ static MavenBanAuditContext empty() {
    return new MavenBanAuditContext(null, List.of(), new ArtifactClassIndex(Map.of()));
  }

  /* package */ String identityFingerprint() {
    return inventory == null ? "none" : inventory.fingerprint();
  }

  /* package */ static MavenBanAuditContext create(
      final MavenOriginalInputAudit.Inventory original,
      final MavenAnalysisResolutionContext effective)
      throws IOException {
    if (original == null) {
      return empty();
    }
    validateProjectIdentity(original, effective);
    final List<MavenOriginalInputAudit.AuditArtifact> auditOnly =
        auditOnlyArtifacts(original, effective);
    final ArtifactClassIndex index = auditOnlyClassIndex(auditOnly);
    return new MavenBanAuditContext(original, auditOnly, index);
  }

  private static void validateProjectIdentity(
      final MavenOriginalInputAudit.Inventory original,
      final MavenAnalysisResolutionContext effective)
      throws IOException {
    if (!original
            .project()
            .equals(BanishedDependencyOriginalModel.projectIdentity(effective.liveProject()))
        || !original
            .graph()
            .projectKey()
            .equals(MavenElisionGraphBinding.projectKey(effective.project()))) {
      throw new IOException("Original-input audit belongs to a different Maven project");
    }
  }

  private static List<MavenOriginalInputAudit.AuditArtifact> auditOnlyArtifacts(
      final MavenOriginalInputAudit.Inventory original,
      final MavenAnalysisResolutionContext effective)
      throws IOException {
    final Set<EffectiveGraphDecisionIndex.Gavce> originalReachable =
        reachableArtifacts(original.graph());
    final Set<EffectiveGraphDecisionIndex.Gavce> effectiveReachable =
        reachableArtifacts(effective.pair().after());
    final Map<EffectiveGraphDecisionIndex.Gavce, MavenOriginalInputAudit.AuditArtifact>
        originalArtifacts = originalArtifacts(original.resolvedArtifacts());
    if (!originalArtifacts.keySet().equals(originalReachable)) {
      throw new IOException("Original audit graph does not match its reachable provider inventory");
    }
    if (!effectiveReachable.equals(effectiveArtifacts(effective))) {
      throw new IOException("Effective graph does not match its reachable provider inventory");
    }
    return originalArtifacts.entrySet().stream()
        .filter(entry -> !effectiveReachable.contains(entry.getKey()))
        .map(Map.Entry::getValue)
        .sorted(java.util.Comparator.comparing(MavenOriginalInputAudit.AuditArtifact::coordinate))
        .toList();
  }

  private static ArtifactClassIndex auditOnlyClassIndex(
      final List<MavenOriginalInputAudit.AuditArtifact> auditOnly) throws IOException {
    final List<ArtifactFileRef> classProviders = new ArrayList<>();
    for (final MavenOriginalInputAudit.AuditArtifact artifact : auditOnly) {
      if (!"jar".equals(artifact.coordinate().type()) || !"jar".equals(artifact.mavenType())) {
        throw new IOException(
            "Cannot establish original-only provider closure for unsupported artifact: "
                + artifact.coordinate()
                + " (Maven type: "
                + artifact.mavenType()
                + ")");
      }
      if (artifact.filePath() == null || artifact.sha256() == null) {
        throw new IOException(
            "Original-only provider has no audited bytes: " + artifact.coordinate());
      }
      final Path path = Path.of(artifact.filePath()).toAbsolutePath().normalize();
      verifyArtifactBytes(artifact, path);
      classProviders.add(ArtifactFileRef.fromPath(artifact.coordinate(), path));
    }
    return new JarIndexScanner().scan(classProviders);
  }

  /* package */ void verifyArtifactBytes() throws IOException {
    final List<MavenOriginalInputAudit.AuditArtifact> values =
        inventory == null ? auditOnlyArtifacts : inventory.resolvedArtifacts();
    for (final MavenOriginalInputAudit.AuditArtifact artifact : values) {
      if (artifact.filePath() == null) {
        if (auditOnlyArtifacts.stream()
            .anyMatch(value -> sameGavce(value.coordinate(), artifact.coordinate()))) {
          throw new IOException(
              "Original-only provider has no audited bytes: " + artifact.coordinate());
        }
        continue;
      }
      if (artifact.sha256() == null) {
        throw new IOException(
            "Original-input artifact has no audited digest: " + artifact.coordinate());
      }
      verifyArtifactBytes(artifact, Path.of(artifact.filePath()).toAbsolutePath().normalize());
    }
  }

  private static void verifyArtifactBytes(
      final MavenOriginalInputAudit.AuditArtifact artifact, final Path path) throws IOException {
    if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
      throw new IOException("Original-only provider is no longer readable: " + path);
    }
    if (!artifact.sha256().equals(ArtifactFileDigest.sha256(path))) {
      throw new IOException("Original-only provider bytes changed after audit: " + path);
    }
  }

  /* package */ void verifyEvidence(final MavenAnalysisEvidence.RootEvidence evidence)
      throws MojoFailureException {
    for (final Map.Entry<ArtifactCoordinate, Set<ArtifactCoordinate>> providers :
        evidence.dynamicRoots().resourceProvidersByDeclaringArtifact().entrySet()) {
      for (final ArtifactCoordinate provider : providers.getValue()) {
        if (auditOnlyArtifacts.stream()
            .anyMatch(artifact -> sameGavce(artifact.coordinate(), provider))) {
          throw MavenBanClassProviderClosure.conflict(
              provider, "retained resource or provider metadata requires the artifact");
        }
      }
    }
  }

  /* package */ void verifyRetainedClosure(
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final ElisionDecision effectiveDecision,
      final TrimAnalysisResult trimAnalysis,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final Map<ArtifactCoordinate, Set<String>> forcedAbsentClassProviders)
      throws IOException, MojoFailureException {
    if (auditOnlyArtifacts.isEmpty() && forcedAbsentClassProviders.isEmpty()) {
      return;
    }
    verifyArtifactBytes();
    final Map<String, List<ArtifactCoordinate>> absentOwners = ownersByClass(auditOnlyClassIndex);
    forcedAbsentClassProviders.forEach(
        (coordinate, classes) ->
            classes.forEach(className -> addOwner(absentOwners, className, coordinate)));
    normalizeOwners(absentOwners);
    final Map<String, List<ArtifactCoordinate>> effectiveOwners = ownersByClass(prepared.index());
    verifyRequiredClasses(
        prepared, effectiveDecision.retainedArtifacts(), absentOwners, effectiveOwners);
    MavenBanRetainedBytecodeClosure.verify(
        prepared, effectiveDecision, trimAnalysis, forcedUnchanged, absentOwners, effectiveOwners);
    MavenBanRetainedMetadataClosure.verify(
        prepared, effectiveDecision.retainedArtifacts(), absentOwners, effectiveOwners);
    MavenBanRetainedResourceClosure.verify(
        auditOnlyArtifacts, prepared, effectiveDecision.retainedArtifacts());
    verifyArtifactBytes();
  }

  private static void verifyRequiredClasses(
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retained,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners)
      throws MojoFailureException {
    final Set<String> required = new TreeSet<>(prepared.trace().loadedClassesDotFormat());
    required.addAll(prepared.sourceRequiredClasses());
    prepared.bytecodeScan().ifPresent(scan -> required.addAll(scan.referencedClasses()));
    for (final String className : required) {
      MavenBanClassProviderClosure.verifyReference(
          className,
          "application evidence",
          absentOwners,
          effectiveOwners,
          retained,
          prepared.projectOutputClasses());
    }
  }

  private static Map<EffectiveGraphDecisionIndex.Gavce, MavenOriginalInputAudit.AuditArtifact>
      originalArtifacts(final List<MavenOriginalInputAudit.AuditArtifact> artifacts)
          throws IOException {
    final Map<EffectiveGraphDecisionIndex.Gavce, MavenOriginalInputAudit.AuditArtifact> result =
        new ConcurrentHashMap<>();
    for (final MavenOriginalInputAudit.AuditArtifact artifact : artifacts) {
      final EffectiveGraphDecisionIndex.Gavce key =
          EffectiveGraphDecisionIndex.Gavce.of(artifact.coordinate());
      final MavenOriginalInputAudit.AuditArtifact previous = result.putIfAbsent(key, artifact);
      if (previous != null
          && (!java.util.Objects.equals(previous.filePath(), artifact.filePath())
              || !java.util.Objects.equals(previous.sha256(), artifact.sha256())
              || !previous.mavenType().equals(artifact.mavenType()))) {
        throw new IOException("Original Resolver has ambiguous provider variants for " + key);
      }
    }
    return result;
  }

  private static Map<String, List<ArtifactCoordinate>> ownersByClass(
      final ArtifactClassIndex index) {
    final Map<String, List<ArtifactCoordinate>> owners = new ConcurrentHashMap<>();
    index
        .classesByArtifact()
        .forEach(
            (artifact, classes) ->
                classes.forEach(className -> addOwner(owners, className, artifact.coordinate())));
    normalizeOwners(owners);
    return owners;
  }

  private static void normalizeOwners(final Map<String, List<ArtifactCoordinate>> owners) {
    owners.replaceAll((ignored, coordinates) -> List.copyOf(new TreeSet<>(coordinates)));
  }

  private static void addOwner(
      final Map<String, List<ArtifactCoordinate>> owners,
      final String className,
      final ArtifactCoordinate coordinate) {
    owners.computeIfAbsent(className, ignored -> new ArrayList<>()).add(coordinate);
  }

  private static Set<EffectiveGraphDecisionIndex.Gavce> effectiveArtifacts(
      final MavenAnalysisResolutionContext context) {
    return context.artifacts().resolvedSnapshots().stream()
        .map(snapshot -> EffectiveGraphDecisionIndex.Gavce.of(snapshot.coordinate()))
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
  }

  private static Set<EffectiveGraphDecisionIndex.Gavce> reachableArtifacts(
      final ResolverArtifactGraphSnapshot graph) throws IOException {
    final Set<EffectiveGraphDecisionIndex.Gavce> result = new java.util.LinkedHashSet<>();
    for (final Map<String, Object> node : graph.nodes()) {
      if (!Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))
          || java.util.Objects.equals(
              node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID), graph.rootNodeId())) {
        continue;
      }
      final EffectiveGraphDecisionIndex.Gavce identity = EffectiveGraphDecisionIndex.gavce(node);
      if (identity == null) {
        throw new IOException("Resolver graph has an incomplete reachable artifact identity");
      }
      result.add(identity);
    }
    return Set.copyOf(result);
  }

  private static boolean sameGavce(final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return EffectiveGraphDecisionIndex.Gavce.of(left)
        .equals(EffectiveGraphDecisionIndex.Gavce.of(right));
  }
}
