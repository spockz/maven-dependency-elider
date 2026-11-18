// WHY: Defines immutable inputs and results shared by Maven elision collaborators.

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.MavenDependencyTrimmer.MIN_TRIM_WORKERS;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRoots;
import io.github.spockz.elider.plugin.nativeimage.NativeImageConsumedInput;
import io.github.spockz.elider.plugin.nativeimage.NativeImageScanContext;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Defines immutable inputs and results shared by Maven elision collaborators. */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public final class ElisionAnalysisModel {
  private ElisionAnalysisModel() {}

  /** Model data record for {@code AnalysisOptions}. */
  public record AnalysisOptions(
      List<File> traceFiles,
      List<String> retainedArtifacts,
      List<String> banishedDependencies,
      File productionOutput,
      MavenSession session,
      CompletenessOptions completeness,
      TrimOptions trim,
      DynamicRootOptions dynamicRoots,
      AnalysisEnvironment environment,
      boolean closedWorld) {
    /* default */ AnalysisOptions(
        final List<File> traceFiles,
        final List<String> retainedArtifacts,
        final List<String> banishedDependencies,
        final File productionOutput,
        final MavenSession session,
        final CompletenessOptions completeness,
        final TrimOptions trim,
        final DynamicRootOptions dynamicRoots,
        final AnalysisEnvironment environment) {
      this(
          traceFiles,
          retainedArtifacts,
          banishedDependencies,
          productionOutput,
          session,
          completeness,
          trim,
          dynamicRoots,
          environment,
          false);
    }

    /* default */ AnalysisOptions(
        final List<File> traceFiles,
        final List<String> retainedArtifacts,
        final List<String> banishedDependencies,
        final File productionOutput,
        final MavenSession session,
        final CompletenessOptions completeness,
        final TrimOptions trim,
        final DynamicRootOptions dynamicRoots) {
      this(
          traceFiles,
          retainedArtifacts,
          banishedDependencies,
          productionOutput,
          session,
          completeness,
          trim,
          dynamicRoots,
          null,
          false);
    }

    /* default */ AnalysisOptions(
        final List<File> traceFiles,
        final List<String> retainedArtifacts,
        final File productionOutput,
        final MavenSession session,
        final CompletenessOptions completeness,
        final TrimOptions trim,
        final DynamicRootOptions dynamicRoots) {
      this(
          traceFiles,
          retainedArtifacts,
          List.of(),
          productionOutput,
          session,
          completeness,
          trim,
          dynamicRoots,
          null,
          false);
    }

    /** Validates and normalizes {@code AnalysisOptions}. */
    public AnalysisOptions {
      retainedArtifacts = retainedArtifacts == null ? List.of() : List.copyOf(retainedArtifacts);
      banishedDependencies =
          banishedDependencies == null ? List.of() : List.copyOf(banishedDependencies);
      if (trim.workers() < MIN_TRIM_WORKERS) {
        throw new IllegalArgumentException("trimWorkers must be at least 1");
      }
      // Validates mrjarStrategy parsing
      MrjarStrategy.parse(trim.mrjarStrategy());
    }

    /* default */ AnalysisOptions withEnvironment(final AnalysisEnvironment value) {
      return new AnalysisOptions(
          traceFiles,
          retainedArtifacts,
          banishedDependencies,
          productionOutput,
          null,
          completeness,
          trim,
          dynamicRoots,
          value,
          closedWorld);
    }
  }

  /** Model data record for {@code CompletenessOptions}. */
  public record CompletenessOptions(
      boolean sourceRootsComplete,
      boolean productionClassesComplete,
      boolean trustedProcessClassesContext,
      boolean testResolutionContext) {}

  /** Model data record for {@code TrimOptions}. */
  public record TrimOptions(
      boolean enabled,
      List<String> explicitRoots,
      boolean failOnUnsupportedMultiRelease,
      List<String> passThroughArtifacts,
      boolean failOnUnsupportedModuleInfo,
      int workers,
      String mrjarStrategy,
      PluginCacheProducerIdentityResolver.Resolution cacheProducerResolution,
      DuplicateClassPolicy duplicateClasses,
      boolean passThroughOnUnresolved) {
    /** Validates and normalizes {@code TrimOptions}. */
    public TrimOptions {
      java.util.Objects.requireNonNull(cacheProducerResolution, "cacheProducerResolution");
      java.util.Objects.requireNonNull(duplicateClasses, "duplicateClasses");
    }

    /* default */ TrimOptions(
        final boolean enabled,
        final List<String> explicitRoots,
        final boolean failOnUnsupportedMultiRelease,
        final List<String> passThroughArtifacts,
        final boolean failOnUnsupportedModuleInfo,
        final int workers,
        final String mrjarStrategy,
        final PluginCacheProducerIdentityResolver.Resolution cacheProducerResolution,
        final DuplicateClassPolicy duplicateClasses) {
      this(
          enabled,
          explicitRoots,
          failOnUnsupportedMultiRelease,
          passThroughArtifacts,
          failOnUnsupportedModuleInfo,
          workers,
          mrjarStrategy,
          cacheProducerResolution,
          duplicateClasses,
          false);
    }

    /* default */ TrimOptions(
        final boolean enabled,
        final List<String> explicitRoots,
        final boolean failOnUnsupportedMultiRelease,
        final List<String> passThroughArtifacts,
        final boolean failOnUnsupportedModuleInfo,
        final int workers,
        final String mrjarStrategy,
        final PluginCacheProducerIdentityResolver.Resolution cacheProducerResolution) {
      this(
          enabled,
          explicitRoots,
          failOnUnsupportedMultiRelease,
          passThroughArtifacts,
          failOnUnsupportedModuleInfo,
          workers,
          mrjarStrategy,
          cacheProducerResolution,
          DuplicateClassPolicy.NONE);
    }

    /* default */ TrimOptions(
        final boolean enabled,
        final List<String> explicitRoots,
        final boolean failOnUnsupportedMultiRelease,
        final List<String> passThroughArtifacts,
        final boolean failOnUnsupportedModuleInfo,
        final int workers,
        final String mrjarStrategy) {
      this(
          enabled,
          explicitRoots,
          failOnUnsupportedMultiRelease,
          passThroughArtifacts,
          failOnUnsupportedModuleInfo,
          workers,
          mrjarStrategy,
          unresolvedTrimCacheProducer());
    }
  }

  private static PluginCacheProducerIdentityResolver.Resolution unresolvedTrimCacheProducer() {
    return new PluginCacheProducerIdentityResolver.Resolution(
        Optional.empty(), Optional.of("Trim cache producer identity was not provided"));
  }

  /** Model data record for {@code DynamicRootOptions}. */
  public record DynamicRootOptions(boolean conservativeServiceLoaderRoots) {}

  /** Scans one dependency archive during an analysis invocation. */
  /* default */
  @FunctionalInterface
  public interface DynamicRootScanner {
    /** Returns the dynamic roots declared by the archive. */
    DependencyDynamicRoots.RootScan scan(Path path, NativeImageScanContext context)
        throws IOException;
  }

  /** Holds invocation roots and the scans reused by retained-JAR trimming. */
  public record DynamicRootInputs(
      Set<String> classNames,
      Set<ArtifactCoordinate> declaringArtifacts,
      Set<ArtifactCoordinate> resourceProviderArtifacts,
      Map<ArtifactCoordinate, Set<String>> classRootsByDeclaringArtifact,
      Map<ArtifactCoordinate, Set<ArtifactCoordinate>> resourceProvidersByDeclaringArtifact,
      Map<Path, DependencyDynamicRoots.RootScan> scansByPath,
      Map<ArtifactCoordinate, Set<String>> unprovenServiceRootsByCoordinate,
      Set<String> provenServiceInterfaces,
      List<NativeImageConsumedInput> consumedInputs) {
    /** Validates and normalizes {@code DynamicRootInputs}. */
    public DynamicRootInputs {
      classNames = Set.copyOf(classNames);
      declaringArtifacts = Set.copyOf(declaringArtifacts);
      resourceProviderArtifacts = Set.copyOf(resourceProviderArtifacts);
      classRootsByDeclaringArtifact = immutableSets(classRootsByDeclaringArtifact);
      resourceProvidersByDeclaringArtifact = immutableSets(resourceProvidersByDeclaringArtifact);
      scansByPath = Map.copyOf(scansByPath);
      unprovenServiceRootsByCoordinate = Map.copyOf(unprovenServiceRootsByCoordinate);
      provenServiceInterfaces = Set.copyOf(provenServiceInterfaces);
      consumedInputs = NativeImageConsumedInput.ordered(consumedInputs);
    }

    /* default */ DynamicRootInputs(
        final Set<String> classNames,
        final Set<ArtifactCoordinate> declaringArtifacts,
        final Map<Path, DependencyDynamicRoots.RootScan> scansByPath) {
      this(
          classNames,
          declaringArtifacts,
          Set.of(),
          Map.of(),
          Map.of(),
          scansByPath,
          Map.of(),
          Set.of(),
          List.of());
    }

    private static <T> Map<ArtifactCoordinate, Set<T>> immutableSets(
        final Map<ArtifactCoordinate, Set<T>> values) {
      return values.entrySet().stream()
          .collect(
              java.util.stream.Collectors.toUnmodifiableMap(
                  Map.Entry::getKey, entry -> Set.copyOf(entry.getValue())));
    }
  }

  /** Model data record for {@code PreparedAnalysis}. */
  public record PreparedAnalysis(
      MavenProject project,
      AnalysisOptions options,
      List<ArtifactSnapshot> resolvedSnapshots,
      boolean directArtifactsPresent,
      List<ArtifactSnapshot> directSnapshots,
      ElisionDecision traceDecision,
      ElisionDecision rawDecision,
      ClassUsageReport classUsageReport,
      Optional<BytecodeReferenceScan> bytecodeScan,
      List<ArtifactFileRef> scanCandidates,
      TraceData trace,
      ArtifactClassIndex index,
      DynamicRootInputs dynamicRootInputs,
      Set<String> projectOutputClasses,
      Set<String> sourceRequiredClasses,
      Set<String> pruningRequiredClasses,
      String productionOutputFingerprint,
      String inputFingerprint,
      String directInputFingerprint,
      MavenElisionGraphBinding.Result graphBinding,
      MavenElisionPolicyIdentity.Options policyOptions,
      String sourceAttributionFallback,
      MavenAnalysisResolutionContext resolutionContext,
      MavenBanPlan banPlan) {
    /** Validates and normalizes {@code PreparedAnalysis}. */
    public PreparedAnalysis {
      resolvedSnapshots = List.copyOf(resolvedSnapshots);
      directSnapshots = List.copyOf(directSnapshots);
      java.util.Objects.requireNonNull(policyOptions, "policyOptions");
      scanCandidates = List.copyOf(scanCandidates);
      projectOutputClasses = Set.copyOf(projectOutputClasses);
      sourceRequiredClasses = Set.copyOf(sourceRequiredClasses);
      pruningRequiredClasses = Set.copyOf(pruningRequiredClasses);
      java.util.Objects.requireNonNull(productionOutputFingerprint, "productionOutputFingerprint");
      java.util.Objects.requireNonNull(banPlan, "banPlan");
    }
  }

  /** Model data record for {@code EffectiveAnalysis}. */
  public record EffectiveAnalysis(
      PreparedAnalysis prepared,
      MavenBanPlan banPlan,
      EffectiveGraphPolicy.Evaluation graphEvaluation,
      ElisionDecision rawDecision,
      ElisionDecision effectiveDecision,
      Set<ArtifactCoordinate> forcedUnchangedCoordinates,
      TrimAnalysisResult trimAnalysis,
      String inventoryFingerprint,
      String operationFingerprint,
      ResolverArtifactGraphProjection graphProjection) {
    /** Validates and normalizes {@code EffectiveAnalysis}. */
    public EffectiveAnalysis {
      if (!prepared.banPlan().equals(banPlan)) {
        throw new IllegalArgumentException("Effective analysis changed its prepared ban plan");
      }
      forcedUnchangedCoordinates = Set.copyOf(forcedUnchangedCoordinates);
    }
  }

  /** Model data record for {@code ArtifactViews}. */
  public record ArtifactViews(
      List<ArtifactSnapshot> resolvedSnapshots,
      boolean directArtifactsPresent,
      List<ArtifactSnapshot> directSnapshots) {
    /** Validates and normalizes {@code ArtifactViews}. */
    public ArtifactViews {
      resolvedSnapshots = List.copyOf(resolvedSnapshots);
      directSnapshots = List.copyOf(directSnapshots);
    }

    /* default */ Set<Artifact> resolvedArtifacts() {
      return references(resolvedSnapshots);
    }

    /* default */ Set<Artifact> directArtifacts() {
      return references(directSnapshots);
    }

    private static Set<Artifact> references(final List<ArtifactSnapshot> snapshots) {
      final Set<Artifact> result = new LinkedHashSet<>();
      snapshots.stream().map(ArtifactSnapshot::artifact).forEach(result::add);
      return Collections.unmodifiableSet(result);
    }
  }

  /** Model data record for {@code AnalysisEvidence}. */
  public record AnalysisEvidence(
      ClassUsageReport classUsageReport,
      Optional<BytecodeReferenceScan> bytecodeScan,
      Map<ArtifactCoordinate, Set<String>> unprovenServiceRoots,
      boolean productionClassesComplete,
      boolean trustedProcessClassesContext,
      String sourceAttributionFallback,
      Set<String> projectOutputClasses,
      List<String> unresolvedDynamicRootDiagnostics) {
    /** Validates and normalizes {@code AnalysisEvidence}. */
    public AnalysisEvidence {
      unprovenServiceRoots =
          unprovenServiceRoots != null ? Map.copyOf(unprovenServiceRoots) : Map.of();
      projectOutputClasses =
          projectOutputClasses == null ? Set.of() : Set.copyOf(projectOutputClasses);
      unresolvedDynamicRootDiagnostics = List.copyOf(unresolvedDynamicRootDiagnostics);
    }

    /* default */ AnalysisEvidence(
        final ClassUsageReport classUsageReport,
        final Optional<BytecodeReferenceScan> bytecodeScan,
        final Map<ArtifactCoordinate, Set<String>> unprovenServiceRoots,
        final boolean productionClassesComplete,
        final boolean trustedProcessClassesContext,
        final String sourceAttributionFallback,
        final Set<String> projectOutputClasses) {
      this(
          classUsageReport,
          bytecodeScan,
          unprovenServiceRoots,
          productionClassesComplete,
          trustedProcessClassesContext,
          sourceAttributionFallback,
          projectOutputClasses,
          List.of());
    }

    /* package */ AnalysisEvidence(
        final ClassUsageReport classUsageReport,
        final Optional<BytecodeReferenceScan> bytecodeScan,
        final Map<ArtifactCoordinate, Set<String>> unprovenServiceRoots,
        final boolean productionClassesComplete,
        final boolean trustedProcessClassesContext,
        final String sourceAttributionFallback) {
      this(
          classUsageReport,
          bytecodeScan,
          unprovenServiceRoots,
          productionClassesComplete,
          trustedProcessClassesContext,
          sourceAttributionFallback,
          Set.of());
    }
  }

  /** Model data record for {@code Analysis}. */
  public record Analysis(
      ArtifactViews artifacts,
      ElisionDecision decision,
      ElisionDecision effectiveDecision,
      AnalysisEvidence evidence,
      TrimResult trimResult,
      ResolverArtifactGraphProjection graphProjection,
      MediatedGraphReport mediatedGraph,
      MavenElisionPolicyIdentity policyIdentity,
      ElisionDecision traceDecision,
      MavenBanPlan banPlan) {
    /* default */ Analysis(
        final ArtifactViews artifacts,
        final ElisionDecision decision,
        final ElisionDecision effectiveDecision,
        final AnalysisEvidence evidence,
        final TrimResult trimResult,
        final ResolverArtifactGraphProjection graphProjection,
        final MediatedGraphReport mediatedGraph,
        final MavenElisionPolicyIdentity policyIdentity) {
      this(
          artifacts,
          decision,
          effectiveDecision,
          evidence,
          trimResult,
          graphProjection,
          mediatedGraph,
          policyIdentity,
          decision,
          MavenBanPlan.empty());
    }
  }

  /* default */ static ArtifactViews artifactViews(final PreparedAnalysis prepared) {
    return new ArtifactViews(
        prepared.resolvedSnapshots(),
        prepared.directArtifactsPresent(),
        prepared.directSnapshots());
  }

  /* default */ static AnalysisEvidence evidence(final PreparedAnalysis prepared) {
    final AnalysisOptions options = prepared.options();
    final CompletenessOptions completeness = options.completeness();
    final DynamicRootInputs dynamicRoots = prepared.dynamicRootInputs();
    return new AnalysisEvidence(
        prepared.classUsageReport(),
        prepared.bytecodeScan(),
        dynamicRoots.unprovenServiceRootsByCoordinate(),
        completeness.productionClassesComplete(),
        completeness.trustedProcessClassesContext(),
        prepared.sourceAttributionFallback(),
        prepared.projectOutputClasses(),
        DynamicRootDiagnostics.unresolvedRoots(
            dynamicRoots.classRootsByDeclaringArtifact(),
            prepared.index().classesByArtifact().values().stream()
                .flatMap(Set::stream)
                .collect(java.util.stream.Collectors.toSet()),
            prepared.projectOutputClasses()));
  }

  /** Model data record for {@code ArtifactSnapshot}. */
  public record ArtifactSnapshot(Artifact artifact, ArtifactCoordinate coordinate, Path filePath)
      implements BanishedDependencyPolicy.ArtifactCandidate {
    /* default */ static ArtifactSnapshot from(final Artifact artifact) {
      return new ArtifactSnapshot(
          artifact,
          MavenArtifactInventory.toCoordinate(artifact),
          MavenArtifactInventory.normalizedPath(artifact));
    }
  }

  /** Model data record for {@code ApplyPlan}. */
  public record ApplyPlan(
      Set<Artifact> resolvedArtifacts,
      Set<Artifact> originalResolvedArtifacts,
      boolean directArtifactsPresent,
      Set<Artifact> directArtifacts) {
    /** Validates and normalizes {@code ApplyPlan}. */
    public ApplyPlan {
      resolvedArtifacts = Collections.unmodifiableSet(new LinkedHashSet<>(resolvedArtifacts));
      originalResolvedArtifacts =
          Collections.unmodifiableSet(new LinkedHashSet<>(originalResolvedArtifacts));
      directArtifacts = Collections.unmodifiableSet(new LinkedHashSet<>(directArtifacts));
    }

    /* default */ ApplyPlan(
        final Set<Artifact> resolvedArtifacts,
        final boolean directArtifactsPresent,
        final Set<Artifact> directArtifacts) {
      this(resolvedArtifacts, resolvedArtifacts, directArtifactsPresent, directArtifacts);
    }
  }

  /** Model data record for {@code CurrentViews}. */
  public record CurrentViews(List<Artifact> resolvedArtifacts, List<Artifact> directArtifacts) {
    /** Validates and normalizes {@code CurrentViews}. */
    public CurrentViews {
      resolvedArtifacts = List.copyOf(resolvedArtifacts);
      directArtifacts = List.copyOf(directArtifacts);
    }
  }
}
