// WHY: Defines immutable inputs and results shared by Maven elision collaborators.

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.MavenDependencyTrimmer.MIN_TRIM_WORKERS;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
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
final class ElisionAnalysisModel {
  private ElisionAnalysisModel() {}

  /* default */ record AnalysisOptions(
      List<File> traceFiles,
      List<String> retainedArtifacts,
      List<String> banishedDependencies,
      File productionOutput,
      MavenSession session,
      CompletenessOptions completeness,
      TrimOptions trim,
      DynamicRootOptions dynamicRoots,
      AnalysisEnvironment environment) {
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
          null);
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
          null);
    }

    /* default */ AnalysisOptions {
      retainedArtifacts = retainedArtifacts == null ? List.of() : List.copyOf(retainedArtifacts);
      banishedDependencies =
          banishedDependencies == null ? List.of() : List.copyOf(banishedDependencies);
      if (trim.workers() < MIN_TRIM_WORKERS) {
        throw new IllegalArgumentException("trimWorkers must be at least 1");
      }
      if (!MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING.equals(trim.mrjarStrategy())
          && !MavenDependencyTrimmer.MRJAR_PASS_THROUGH.equals(trim.mrjarStrategy())
          && !MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY.equals(trim.mrjarStrategy())) {
        throw new IllegalArgumentException(
            "elide.mrjarStrategy must be vertical-shading, pass-through, or classpath-only");
      }
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
          value);
    }
  }

  /* default */ record CompletenessOptions(
      boolean sourceRootsComplete,
      boolean productionClassesComplete,
      boolean trustedProcessClassesContext,
      boolean testResolutionContext) {}

  /* default */ record TrimOptions(
      boolean enabled,
      List<String> explicitRoots,
      boolean failOnUnsupportedMultiRelease,
      List<String> passThroughArtifacts,
      boolean failOnUnsupportedModuleInfo,
      int workers,
      String mrjarStrategy,
      PluginCacheProducerIdentityResolver.Resolution cacheProducerResolution) {
    /* default */ TrimOptions {
      java.util.Objects.requireNonNull(cacheProducerResolution, "cacheProducerResolution");
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

  /* default */ record DynamicRootOptions(boolean conservativeServiceLoaderRoots) {}

  /** Scans one dependency archive during an analysis invocation. */
  /* default */
  @FunctionalInterface
  interface DynamicRootScanner {
    /** Returns the dynamic roots declared by the archive. */
    DependencyDynamicRoots.RootScan scan(Path path, NativeImageScanContext context)
        throws IOException;
  }

  /** Holds invocation roots and the scans reused by retained-JAR trimming. */
  /* default */ record DynamicRootInputs(
      Set<String> classNames,
      Set<ArtifactCoordinate> declaringArtifacts,
      Set<ArtifactCoordinate> resourceProviderArtifacts,
      Map<ArtifactCoordinate, Set<String>> classRootsByDeclaringArtifact,
      Map<ArtifactCoordinate, Set<ArtifactCoordinate>> resourceProvidersByDeclaringArtifact,
      Map<Path, DependencyDynamicRoots.RootScan> scansByPath,
      Map<ArtifactCoordinate, Set<String>> unprovenServiceRootsByCoordinate,
      Set<String> provenServiceInterfaces,
      List<NativeImageConsumedInput> consumedInputs) {
    /* default */ DynamicRootInputs {
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

  /* default */ record PreparedAnalysis(
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
    /* default */ PreparedAnalysis {
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

  /* default */ record EffectiveAnalysis(
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
    /* default */ EffectiveAnalysis {
      if (!prepared.banPlan().equals(banPlan)) {
        throw new IllegalArgumentException("Effective analysis changed its prepared ban plan");
      }
      forcedUnchangedCoordinates = Set.copyOf(forcedUnchangedCoordinates);
    }
  }

  /* default */ record ArtifactViews(
      List<ArtifactSnapshot> resolvedSnapshots,
      boolean directArtifactsPresent,
      List<ArtifactSnapshot> directSnapshots) {
    /* default */ ArtifactViews {
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

  /* default */ record AnalysisEvidence(
      ClassUsageReport classUsageReport,
      Optional<BytecodeReferenceScan> bytecodeScan,
      Map<ArtifactCoordinate, Set<String>> unprovenServiceRoots,
      boolean productionClassesComplete,
      boolean trustedProcessClassesContext,
      String sourceAttributionFallback,
      Set<String> projectOutputClasses) {
    /* default */ AnalysisEvidence {
      unprovenServiceRoots =
          unprovenServiceRoots != null ? Map.copyOf(unprovenServiceRoots) : Map.of();
      projectOutputClasses =
          projectOutputClasses == null ? Set.of() : Set.copyOf(projectOutputClasses);
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

  /* default */ record Analysis(
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
        prepared.projectOutputClasses());
  }

  /* default */ record ArtifactSnapshot(
      Artifact artifact, ArtifactCoordinate coordinate, Path filePath) {
    /* default */ static ArtifactSnapshot from(final Artifact artifact) {
      return new ArtifactSnapshot(
          artifact,
          MavenArtifactInventory.toCoordinate(artifact),
          MavenArtifactInventory.normalizedPath(artifact));
    }
  }

  /* default */ record ApplyPlan(
      Set<Artifact> resolvedArtifacts,
      boolean directArtifactsPresent,
      Set<Artifact> directArtifacts) {
    /* default */ ApplyPlan {
      resolvedArtifacts = Collections.unmodifiableSet(new LinkedHashSet<>(resolvedArtifacts));
      directArtifacts = Collections.unmodifiableSet(new LinkedHashSet<>(directArtifacts));
    }
  }

  /* default */ record CurrentViews(
      List<Artifact> resolvedArtifacts, List<Artifact> directArtifacts) {
    /* default */ CurrentViews {
      resolvedArtifacts = List.copyOf(resolvedArtifacts);
      directArtifacts = List.copyOf(directArtifacts);
    }
  }
}
