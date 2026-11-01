// WHY: Combines production bytecode with source attribution and retains
// compiler-visible classes when attribution is incomplete.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.plugin.ProductionAnalysisInputs.CompilerInputs;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Attributes post-compile sources with an explicit conservative fallback. */
final class PostCompileSourceAttribution {
  private PostCompileSourceAttribution() {}

  /* package */ static CompilerInputs analyze(
      final MavenProject project,
      final MavenSession session,
      final List<String> classpath,
      final List<ArtifactFileRef> candidates,
      final Set<ArtifactFileRef> compileVisibleArtifacts,
      final Map<ArtifactFileRef, Set<String>> indexedClasses,
      final Optional<BytecodeReferenceScan> bytecodeScan,
      final Set<String> outputClassNames)
      throws IOException {
    return analyze(
        project,
        session,
        null,
        classpath,
        candidates,
        compileVisibleArtifacts,
        indexedClasses,
        bytecodeScan,
        outputClassNames);
  }

  /* package */ static CompilerInputs analyze(
      final MavenProject project,
      final MavenSession session,
      final AnalysisEnvironment environment,
      final List<String> classpath,
      final List<ArtifactFileRef> candidates,
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
    final Set<String> requiredClasses = new HashSet<>(scan.referencedClasses());
    if (!scan.complete()) {
      return conservativePostCompileInputs(
          compileVisibleArtifacts,
          indexedClasses,
          requiredClasses,
          "Production bytecode reference scan is incomplete");
    }
    try {
      final List<Path> sourceFiles = postCompileSourceFiles(project);
      final List<String> sourceClasspath = new ArrayList<>(classpath);
      final Set<Path> normalizedClasspath =
          ProductionAnalysisInputs.normalizedPaths(sourceClasspath);
      for (final ArtifactFileRef candidate : candidates) {
        if (compileVisibleArtifacts.contains(candidate)
            && normalizedClasspath.add(candidate.filePath().toAbsolutePath().normalize())) {
          sourceClasspath.add(candidate.filePath().toAbsolutePath().normalize().toString());
        }
      }
      final Path output = scan.scope();
      if (normalizedClasspath.add(output)) {
        sourceClasspath.add(output.toString());
      }
      final List<String> sourceOptions =
          environment == null
              ? MavenCompilerSettings.postCompileSourceOptions(project, session)
              : MavenCompilerSettings.postCompileSourceOptionsWithEnvironment(project, environment);
      final JavaSourceReferenceScanner.SourceScan sourceScan =
          new JavaSourceReferenceScanner()
              .scanFilesDetailed(sourceFiles, sourceClasspath, sourceOptions);
      requiredClasses.addAll(sourceScan.referencedTypes());
    } catch (final IOException exception) {
      return conservativePostCompileInputs(
          compileVisibleArtifacts, indexedClasses, requiredClasses, exception.getMessage());
    }
    return ProductionAnalysisInputs.inputsForRequiredClasses(
        compileVisibleArtifacts, indexedClasses, requiredClasses, outputClassNames);
  }

  private static List<Path> postCompileSourceFiles(final MavenProject project) throws IOException {
    final List<String> roots = project.getCompileSourceRoots();
    verifySourceDirectories(roots);
    final List<Path> sources = JavaSourceReferenceScanner.sourceFiles(roots);
    if (sources.isEmpty()) {
      throw new IOException("No Java source files are present in compile source roots");
    }
    if (sources.stream().anyMatch(ProductionAnalysisInputs::isModuleDescriptor)) {
      throw new IOException("Source attribution does not support Java module descriptors");
    }
    return sources;
  }

  private static void verifySourceDirectories(final List<String> roots) throws IOException {
    if (roots.isEmpty()) {
      throw new IOException("No compile source roots are declared");
    }
    for (final String root : roots) {
      if (!Files.isDirectory(Path.of(root))) {
        throw new IOException("Compile source root is missing: " + root);
      }
    }
  }

  private static CompilerInputs conservativePostCompileInputs(
      final Set<ArtifactFileRef> compileVisibleArtifacts,
      final Map<ArtifactFileRef, Set<String>> indexedClasses,
      final Set<String> bytecodeReferences,
      final String reason) {
    final Set<String> retainedClasses = new HashSet<>(bytecodeReferences);
    compileVisibleArtifacts.forEach(
        artifact -> retainedClasses.addAll(indexedClasses.getOrDefault(artifact, Set.of())));
    return new CompilerInputs(
        compileVisibleArtifacts.stream()
            .map(ArtifactFileRef::coordinate)
            .collect(java.util.stream.Collectors.toSet()),
        retainedClasses,
        Set.of(),
        reason == null || reason.isBlank() ? "Source attribution is incomplete" : reason);
  }
}
