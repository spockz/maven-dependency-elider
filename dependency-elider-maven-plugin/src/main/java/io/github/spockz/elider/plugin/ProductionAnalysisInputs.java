// WHY: Resolves compiler and production bytecode roots before artifact pruning.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.scanner.ProductionBytecodeAnalysis;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.project.MavenProject;

/** WHY: Separate helpers preserve distinct Maven classpath and bytecode checks. */
@SuppressWarnings("PMD.TooManyMethods")
final class ProductionAnalysisInputs {
  /** Dependency scopes Maven places on its production compile classpath. */
  private static final Set<String> COMPILE_VISIBLE_SCOPES = Set.of("compile", "provided", "system");

  private ProductionAnalysisInputs() {}

  /** Retains all compiler-visible classes or resolves compiled production output. */
  /* default */ static CompilerInputs compilerInputs(
      final MavenProject project,
      final List<ArtifactFileRef> candidates,
      final ArtifactClassIndex index,
      final boolean productionClassesComplete,
      final Optional<BytecodeReferenceScan> bytecodeScan,
      final Set<String> outputClassNames)
      throws IOException {
    final List<String> classpath;
    try {
      classpath = project.getCompileClasspathElements();
    } catch (final DependencyResolutionRequiredException exception) {
      throw new IOException(
          "Cannot resolve the Maven compile classpath for source analysis", exception);
    }
    final Set<ArtifactFileRef> compileVisibleArtifacts =
        compileVisibleArtifacts(candidates, normalizedPaths(classpath));
    final Set<String> requiredClasses = new HashSet<>();
    final Map<ArtifactFileRef, Set<String>> indexedClasses = index.classesByArtifact();
    if (productionClassesComplete) {
      return postCompileBytecodeInputs(
          compileVisibleArtifacts, indexedClasses, bytecodeScan, outputClassNames);
    } else {
      compileVisibleArtifacts.forEach(
          artifact -> requiredClasses.addAll(indexedClasses.getOrDefault(artifact, Set.of())));
    }
    final Set<ArtifactCoordinate> compileVisibleCoordinates = new HashSet<>();
    compileVisibleArtifacts.forEach(
        artifact -> compileVisibleCoordinates.add(artifact.coordinate()));
    return new CompilerInputs(compileVisibleCoordinates, requiredClasses, Set.of(), null);
  }

  private static CompilerInputs postCompileBytecodeInputs(
      final Set<ArtifactFileRef> compileVisibleArtifacts,
      final Map<ArtifactFileRef, Set<String>> indexedClasses,
      final Optional<BytecodeReferenceScan> bytecodeScan,
      final Set<String> outputClassNames)
      throws IOException {
    final BytecodeReferenceScan scan =
        bytecodeScan.orElseThrow(
            () ->
                new IOException(
                    "elide.productionClassesComplete=true requires a production bytecode scan"));
    if (!scan.complete()) {
      final Set<String> fallbackClasses = new HashSet<>();
      compileVisibleArtifacts.forEach(
          artifact -> fallbackClasses.addAll(indexedClasses.getOrDefault(artifact, Set.of())));
      final Set<ArtifactCoordinate> coordinates = new HashSet<>();
      compileVisibleArtifacts.forEach(artifact -> coordinates.add(artifact.coordinate()));
      return new CompilerInputs(
          coordinates,
          fallbackClasses,
          Set.of(),
          "Production bytecode reference scan is incomplete");
    }
    return inputsForRequiredClasses(
        compileVisibleArtifacts,
        indexedClasses,
        new HashSet<>(scan.referencedClasses()),
        outputClassNames);
  }

  private static Set<ArtifactFileRef> compileVisibleArtifacts(
      final List<ArtifactFileRef> candidates, final Set<Path> compileClasspath) {
    final Set<ArtifactFileRef> visible = new HashSet<>();
    for (final ArtifactFileRef candidate : candidates) {
      if (COMPILE_VISIBLE_SCOPES.contains(candidate.coordinate().scope())
          || compileClasspath.contains(candidate.filePath().toAbsolutePath().normalize())) {
        visible.add(candidate);
      }
    }
    return visible;
  }

  /* package */ static CompilerInputs inputsForRequiredClasses(
      final Set<ArtifactFileRef> artifacts,
      final Map<ArtifactFileRef, Set<String>> indexedClasses,
      final Set<String> requiredClasses,
      final Set<String> declaredClasses) {
    final Set<ArtifactCoordinate> coordinates =
        artifacts.stream()
            .filter(artifact -> sourceClassesByArtifact(artifact, requiredClasses, indexedClasses))
            .map(ArtifactFileRef::coordinate)
            .collect(java.util.stream.Collectors.toSet());
    return new CompilerInputs(coordinates, requiredClasses, declaredClasses, null);
  }

  /* package */ static boolean sourceClassesByArtifact(
      final ArtifactFileRef artifact,
      final Set<String> requiredClasses,
      final Map<ArtifactFileRef, Set<String>> indexedClasses) {
    return indexedClasses.getOrDefault(artifact, Set.of()).stream()
        .anyMatch(requiredClasses::contains);
  }

  /* package */ static Set<Path> normalizedPaths(final List<String> classpath) throws IOException {
    final Set<Path> paths = new HashSet<>();
    for (final String entry : classpath) {
      try {
        paths.add(Path.of(entry).toAbsolutePath().normalize());
      } catch (final InvalidPathException exception) {
        throw new IOException("Invalid Maven compile classpath entry: " + entry, exception);
      }
    }
    return paths;
  }

  /* default */ record CompilerInputs(
      Set<ArtifactCoordinate> compileVisibleCoordinates,
      Set<String> requiredClasses,
      Set<String> declaredClasses,
      String sourceAttributionFallback) {
    /* default */ CompilerInputs {
      compileVisibleCoordinates = Set.copyOf(compileVisibleCoordinates);
      requiredClasses = Set.copyOf(requiredClasses);
      declaredClasses = Set.copyOf(declaredClasses);
    }
  }

  /* default */ record ProductionBytecodeInputs(
      String fingerprint,
      Optional<BytecodeReferenceScan> scan,
      Set<String> provenServiceInterfaces,
      Set<String> outputClassNames) {}

  /* default */ static ProductionBytecodeInputs productionBytecodeInputs(
      final File output, final boolean productionClassesComplete) throws IOException {
    return productionBytecodeInputs(output, List.of(), productionClassesComplete);
  }

  /* default */ static ProductionBytecodeInputs productionBytecodeInputs(
      final File output,
      final List<Path> additionalOutputs,
      final boolean productionClassesComplete)
      throws IOException {
    return productionBytecodeInputs(
        output, additionalOutputs, productionClassesComplete, List.of());
  }

  /* default */ static ProductionBytecodeInputs productionBytecodeInputs(
      final File output,
      final List<Path> additionalOutputs,
      final boolean productionClassesComplete,
      final List<String> compileSourceRoots)
      throws IOException {
    if (output == null) {
      return missingProductionOutput(productionClassesComplete);
    }
    final Path path = output.toPath();
    final ProductionBytecodeAnalysis.Snapshot snapshot =
        ProductionBytecodeAnalysis.capture(path, additionalOutputs);
    requireCompiledProductionClasses(productionClassesComplete, compileSourceRoots, path, snapshot);
    final Set<String> provenServiceInterfaces =
        snapshot.scanServiceLoaderCalls().provenServiceInterfaces();
    return new ProductionBytecodeInputs(
        snapshot.fingerprint(),
        Optional.of(snapshot.bytecodeReferences()),
        provenServiceInterfaces,
        snapshot.classNames());
  }

  private static ProductionBytecodeInputs missingProductionOutput(
      final boolean productionClassesComplete) throws IOException {
    if (productionClassesComplete) {
      throw new IOException(
          "elide.productionClassesComplete=true requires a production class output directory");
    }
    return new ProductionBytecodeInputs("none", Optional.empty(), Set.of(), Set.of());
  }

  private static void requireCompiledProductionClasses(
      final boolean productionClassesComplete,
      final List<String> compileSourceRoots,
      final Path output,
      final ProductionBytecodeAnalysis.Snapshot snapshot)
      throws IOException {
    if (productionClassesComplete
        && snapshot.bytecodeReferences().classFilesScanned() == 0
        && hasJavaSources(compileSourceRoots)) {
      throw new IOException(
          "elide.productionClassesComplete=true requires compiled production class files in "
              + output.toAbsolutePath().normalize()
              + "; run 'mvn compile' first or bind to process-classes");
    }
  }

  private static boolean hasJavaSources(final List<String> sourceRoots) throws IOException {
    for (final String sourceRoot : sourceRoots) {
      final Path root;
      try {
        root = Path.of(sourceRoot);
      } catch (final InvalidPathException exception) {
        throw new IOException("Invalid Maven compile source root: " + sourceRoot, exception);
      }
      if (Files.notExists(root)) {
        continue;
      }
      if (!Files.isDirectory(root)) {
        throw new IOException("Maven compile source root is not a directory: " + root);
      }
      try (Stream<Path> paths = Files.walk(root)) {
        if (paths.anyMatch(
            path -> Files.isRegularFile(path) && path.toString().endsWith(".java"))) {
          return true;
        }
      }
    }
    return false;
  }
}
