// WHY: Supplies a graph-bound service operation for output/cache tests without mutating Maven.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;

/** Builds effective analyses paired with the fixture's exact resolver inventory. */
abstract class MavenElisionServiceEffectiveOutputSupport
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Creates shared fixture support for effective-output tests. */
  protected MavenElisionServiceEffectiveOutputSupport() {
    super();
  }

  /** Builds an operation with the standard Maven trimming options. */
  protected ServiceOperation operation(
      final Fixture fixture, final Path traceFile, final File productionOutput)
      throws IOException, MojoFailureException {
    return operation(fixture, traceFile, productionOutput, true);
  }

  /** Builds an operation with the requested JAR-trimming mode. */
  protected ServiceOperation operation(
      final Fixture fixture,
      final Path traceFile,
      final File productionOutput,
      final boolean trimJars)
      throws IOException, MojoFailureException {
    return operation(fixture, traceFile, productionOutput, trimJars, List.of());
  }

  /** Builds an operation with an explicit trimmer pass-through list. */
  protected ServiceOperation operation(
      final Fixture fixture,
      final Path traceFile,
      final File productionOutput,
      final boolean trimJars,
      final List<String> passThroughArtifacts)
      throws IOException, MojoFailureException {
    return buildOperation(
        fixture, traceFile, productionOutput, List.of(), trimJars, passThroughArtifacts);
  }

  /** Retains coordinates through raw exclusion configuration. */
  protected ServiceOperation operationWithExcludedArtifacts(
      final Fixture fixture,
      final Path traceFile,
      final File productionOutput,
      final List<String> excludedArtifacts,
      final boolean trimJars)
      throws IOException, MojoFailureException {
    return buildOperation(
        fixture, traceFile, productionOutput, excludedArtifacts, trimJars, List.of());
  }

  /** Prepares the operation from raw exclusions and output pass-through coordinates. */
  private ServiceOperation buildOperation(
      final Fixture fixture,
      final Path traceFile,
      final File productionOutput,
      final List<String> excludedArtifacts,
      final boolean trimJars,
      final List<String> passThroughArtifacts)
      throws IOException, MojoFailureException {
    completeSourceRoots(fixture);
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.AnalysisOptions options =
        new MavenElisionService.AnalysisOptions(
            List.of(traceFile.toFile()),
            excludedArtifacts,
            productionOutput,
            null,
            true,
            trimJars,
            List.of(),
            false,
            passThroughArtifacts,
            false,
            true);
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(fixture.mavenProject(), options);
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionServiceEffectiveAnalysisFixtures.graphPairWithAncestorEdges(fixture, false);
    if (!MavenElisionGraphInventory.matchesGraph(pair.after(), prepared.resolvedSnapshots())) {
      throw new IOException("Effective-output fixture graph does not match Maven inventory");
    }
    final EffectiveGraphPolicy.Evaluation evaluation =
        EffectiveGraphPolicy.evaluatePair(pair, prepared.rawDecision());
    final MavenElisionGraphBinding.Result binding =
        new MavenElisionGraphBinding.Result(
            evaluation,
            prepared.graphBinding().inventoryFingerprint(),
            prepared.graphBinding().operationFingerprint(),
            pair);
    return new ServiceOperation(
        service, MavenElisionServiceEffectiveAnalysisFixtures.withBinding(prepared, binding));
  }

  private void completeSourceRoots(final Fixture fixture) throws IOException {
    final Path root = Files.createDirectories(temporaryDirectory.resolve("complete-source"));
    final Path entry = root.resolve("closure/a/Entry.java");
    Files.createDirectories(entry.getParent());
    Files.writeString(entry, "package closure.a; public class Entry {}\n");
    fixture.mavenProject().getBuild().setSourceDirectory(root.toString());
    fixture.mavenProject().addCompileSourceRoot(root.toString());
  }

  /** Runs the isolated effective output engine without changing Maven project views. */
  protected MavenDependencyTrimmer.TrimResult trimEffective(final ServiceOperation operation)
      throws IOException, MojoFailureException {
    return MavenDependencyTrimmer.trimEffectiveOutputs(
        operation.service().finishAnalysis(operation.prepared()));
  }

  /** Writes one trace root using the native trace file format. */
  protected static Path trace(final Path directory, final String className) throws IOException {
    Files.createDirectories(directory);
    final Path file = directory.resolve("runtime.lst");
    Files.writeString(file, className + "\n");
    return file;
  }

  protected record ServiceOperation(
      MavenElisionService service, MavenElisionService.PreparedAnalysis prepared) {}
}
