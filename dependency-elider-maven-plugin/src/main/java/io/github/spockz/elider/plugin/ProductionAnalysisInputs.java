// WHY: Resolves compiler and production bytecode roots before artifact pruning.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.scanner.ProductionBytecodeReferenceScanner;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Resolves compiler and production bytecode roots before artifact pruning. */
final class ProductionAnalysisInputs {
  /** Dependency scopes Maven places on its production compile classpath. */
  private static final Set<String> COMPILE_VISIBLE_SCOPES = Set.of("compile", "provided", "system");

  private ProductionAnalysisInputs() {}

  /* default */ static Set<String> classNamesInOutput(final Path output) throws IOException {
    final Set<String> names = new LinkedHashSet<>();
    try (java.util.stream.Stream<Path> paths = Files.walk(output)) {
      for (final Path path : paths.filter(Files::isRegularFile).toList()) {
        final String name = output.relativize(path).toString().replace('\\', '/');
        if (!name.endsWith(".class")
            || "module-info.class".equals(name)
            || name.endsWith("/module-info.class")) {
          continue;
        }
        names.add(TraceData.normalizeToDot(name.substring(0, name.length() - 6)));
      }
    }
    return Set.copyOf(names);
  }

  /** Resolves source roots or retains all compiler-visible classes. */
  /* default */ static CompilerInputs compilerInputs(
      final MavenProject project,
      final MavenSession session,
      final List<ArtifactFileRef> candidates,
      final ArtifactClassIndex index,
      final boolean sourceRootsComplete,
      final boolean productionClassesComplete,
      final Optional<BytecodeReferenceScan> bytecodeScan)
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
    if (sourceRootsComplete) {
      final List<Path> sources =
          JavaSourceReferenceScanner.sourceFiles(project.getCompileSourceRoots());
      SourceRootCompleteness.verifySourceRootsComplete(project, session, sources);
      if (sources.stream().anyMatch(ProductionAnalysisInputs::isModuleDescriptor)) {
        throw new IOException("Source attribution does not support Java module descriptors");
      }
      final List<String> options = MavenCompilerSettings.options(project, session, classpath);
      final JavaSourceReferenceScanner.SourceScan sourceScan =
          new JavaSourceReferenceScanner().scanFilesDetailed(sources, classpath, options);
      requiredClasses.addAll(sourceScan.referencedTypes());
      return inputsForRequiredClasses(
          compileVisibleArtifacts, indexedClasses, requiredClasses, sourceScan.declaredTypes());
    } else if (productionClassesComplete) {
      return PostCompileSourceAttribution.analyze(
          project,
          session,
          classpath,
          candidates,
          compileVisibleArtifacts,
          indexedClasses,
          bytecodeScan);
    } else {
      compileVisibleArtifacts.forEach(
          artifact -> requiredClasses.addAll(indexedClasses.getOrDefault(artifact, Set.of())));
    }
    final Set<ArtifactCoordinate> compileVisibleCoordinates = new HashSet<>();
    compileVisibleArtifacts.forEach(
        artifact -> compileVisibleCoordinates.add(artifact.coordinate()));
    return new CompilerInputs(compileVisibleCoordinates, requiredClasses, Set.of(), null);
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

  /* package */ static boolean isModuleDescriptor(final Path source) {
    final Path fileName = source.getFileName();
    return fileName != null && "module-info.java".equals(fileName.toString());
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
      String fingerprint, Optional<BytecodeReferenceScan> scan) {}

  /* default */ static ProductionBytecodeInputs productionBytecodeInputs(
      final File output, final boolean productionClassesComplete) throws IOException {
    if (output == null) {
      if (productionClassesComplete) {
        throw new IOException(
            "elide.productionClassesComplete=true requires a production class output directory");
      }
      return new ProductionBytecodeInputs("none", Optional.empty());
    }
    final Path path = output.toPath();
    final String before = ProductionOutputFingerprint.fingerprint(path);
    final BytecodeReferenceScan scan = new ProductionBytecodeReferenceScanner().scan(path);
    if (productionClassesComplete && scan.classFilesScanned() == 0) {
      throw new IOException(
          "elide.productionClassesComplete=true requires compiled production class files in "
              + path.toAbsolutePath().normalize()
              + "; run 'mvn compile' first or bind to process-classes");
    }
    final String after = ProductionOutputFingerprint.fingerprint(path);
    if (!before.equals(after)) {
      throw new IOException("Production output changed during bytecode analysis");
    }
    return new ProductionBytecodeInputs(before, Optional.of(scan));
  }
}
