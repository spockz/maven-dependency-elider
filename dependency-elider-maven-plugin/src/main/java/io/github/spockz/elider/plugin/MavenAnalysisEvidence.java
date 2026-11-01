// WHY: Collects trace, production, and dynamic-root evidence before a raw elision plan is
// calculated.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootInputs;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootScanner;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.scanner.JarIndexScanner;
import io.github.spockz.elider.trace.CompositeTraceReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.project.MavenProject;

/** Collects the independent evidence inputs used by artifact pruning. */
final class MavenAnalysisEvidence {
  private MavenAnalysisEvidence() {}

  /* default */ static RootEvidence scan(
      final MavenProject project,
      final AnalysisOptions options,
      final List<ArtifactFileRef> candidates,
      final DynamicRootScanner scanner)
      throws IOException {
    final TraceData trace = new CompositeTraceReader().readAll(tracePaths(options.traceFiles()));
    final ArtifactClassIndex index = new JarIndexScanner().scan(candidates);
    final CompletenessOptions completeness = options.completeness();
    final ProductionAnalysisInputs.ProductionBytecodeInputs production =
        ProductionAnalysisInputs.productionBytecodeInputs(
            options.productionOutput(), completeness.productionClassesComplete());
    final ProductionAnalysisInputs.CompilerInputs compiler =
        ProductionAnalysisInputs.compilerInputs(
            project,
            options.session(),
            options.environment(),
            candidates,
            index,
            completeness.sourceRootsComplete(),
            completeness.productionClassesComplete(),
            production.scan(),
            production.outputClassNames());
    final NativeImageScanContext scanContext =
        NativeImageScanContext.create(candidates, invocationBaseForProject(project, options));
    final DynamicRootInputs dynamicRoots =
        DynamicRootOrchestrator.dynamicRoots(
            candidates,
            scanner,
            scanContext,
            production.provenServiceInterfaces(),
            options.dynamicRoots().conservativeServiceLoaderRoots());
    return new RootEvidence(
        trace,
        index,
        production.scan(),
        dynamicRoots,
        compiler.declaredClasses(),
        compiler.requiredClasses(),
        compiler.compileVisibleCoordinates(),
        production.outputClassNames(),
        production.fingerprint(),
        compiler.sourceAttributionFallback());
  }

  private static Path invocationBaseForProject(
      final MavenProject project, final AnalysisOptions options) {
    if (options.environment() != null) {
      return options.environment().invocationBase() == null
          ? projectBasePath(project.getBasedir())
          : options.environment().invocationBase();
    }
    return invocationBase(options.request(), project.getBasedir());
  }

  /* package */ static Path invocationBase(
      final MavenExecutionRequest request, final File projectBase) {
    final String requestBase = requestBase(request);
    if (requestBase != null && !requestBase.isBlank()) {
      return Path.of(requestBase).toAbsolutePath().normalize();
    }
    return projectBasePath(projectBase);
  }

  private static String requestBase(final MavenExecutionRequest request) {
    return request == null ? null : request.getBaseDirectory();
  }

  private static Path projectBasePath(final File projectBase) {
    if (projectBase == null) {
      return null;
    }
    final Path path = projectBase.toPath();
    return path.toAbsolutePath().normalize();
  }

  private static List<Path> tracePaths(final List<File> files) {
    return files == null ? List.of() : files.stream().map(File::toPath).toList();
  }

  /* default */ static Set<String> projectOutputClasses(
      final Set<String> declaredClasses, final Set<String> productionOutputClasses) {
    final Set<String> classes = new HashSet<>(declaredClasses);
    classes.addAll(productionOutputClasses);
    return classes;
  }

  /* default */ record RootEvidence(
      TraceData trace,
      ArtifactClassIndex index,
      Optional<BytecodeReferenceScan> bytecodeScan,
      DynamicRootInputs dynamicRoots,
      Set<String> declaredClasses,
      Set<String> sourceRequiredClasses,
      Set<ArtifactCoordinate> compileVisibleCoordinates,
      Set<String> productionOutputClasses,
      String productionOutputFingerprint,
      String sourceAttributionFallback) {}
}
