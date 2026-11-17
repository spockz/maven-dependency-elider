// WHY: Supplies a graph-bound service operation for output/cache tests without mutating Maven.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;

/** Builds effective analyses paired with the fixture's exact resolver inventory. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
abstract class MavenElisionServiceEffectiveOutputSupport
    extends MavenDependencyTrimmerInMemoryClosureSupport {

  /** Creates shared fixture support for effective-output tests. */
  MavenElisionServiceEffectiveOutputSupport() {
    super();
  }

  /** Builds an operation with the standard Maven trimming options. */
  ServiceOperation operation(
      final Fixture fixture, final Path traceFile, final File productionOutput)
      throws IOException, MojoFailureException {
    return operation(fixture, traceFile, productionOutput, true);
  }

  /** Builds an operation with the requested JAR-trimming mode. */
  ServiceOperation operation(
      final Fixture fixture,
      final Path traceFile,
      final File productionOutput,
      final boolean trimJars)
      throws IOException, MojoFailureException {
    return operation(fixture, traceFile, productionOutput, trimJars, List.of());
  }

  /** Builds an operation with an explicit trimmer pass-through list. */
  ServiceOperation operation(
      final Fixture fixture,
      final Path traceFile,
      final File productionOutput,
      final boolean trimJars,
      final List<String> passThroughArtifacts)
      throws IOException, MojoFailureException {
    return operation(
        fixture, traceFile, productionOutput, trimJars, passThroughArtifacts, "vertical-shading");
  }

  /** Builds an operation with explicit MRJAR strategy. */
  ServiceOperation operation(
      final Fixture fixture,
      final Path traceFile,
      final File productionOutput,
      final boolean trimJars,
      final List<String> passThroughArtifacts,
      final String mrjarStrategy)
      throws IOException, MojoFailureException {
    return buildOperation(
        fixture,
        List.of(traceFile),
        productionOutput,
        List.of(),
        trimJars,
        passThroughArtifacts,
        mrjarStrategy,
        MavenPluginDescriptorFixtures.releasedProducerResolution(),
        false);
  }

  /** Prepares an operation using an explicitly selected plugin producer identity. */
  ServiceOperation operationWithProducer(
      final Fixture fixture,
      final Path traceFile,
      final PluginCacheProducerIdentityResolver.Resolution producerResolution)
      throws IOException, MojoFailureException {
    return buildOperation(
        fixture,
        List.of(traceFile),
        null,
        List.of(),
        true,
        List.of(),
        "vertical-shading",
        producerResolution,
        false);
  }

  /** Retains coordinates through raw exclusion configuration. */
  ServiceOperation operationWithExcludedArtifacts(
      final Fixture fixture,
      final Path traceFile,
      final File productionOutput,
      final List<String> retainedArtifacts,
      final boolean trimJars)
      throws IOException, MojoFailureException {
    return buildOperation(
        fixture,
        List.of(traceFile),
        productionOutput,
        retainedArtifacts,
        trimJars,
        List.of(),
        "vertical-shading",
        MavenPluginDescriptorFixtures.releasedProducerResolution(),
        false);
  }

  /** Prepares the operation from raw exclusions and output pass-through coordinates. */
  ServiceOperation buildOperation(
      final Fixture fixture,
      final List<Path> traceFiles,
      final File productionOutput,
      final List<String> retainedArtifacts,
      final boolean trimJars,
      final List<String> passThroughArtifacts,
      final String mrjarStrategy,
      final PluginCacheProducerIdentityResolver.Resolution producerResolution,
      final boolean closedWorld)
      throws IOException, MojoFailureException {
    final File completeOutput =
        completeProductionClasses(
            fixture,
            productionOutput == null
                ? Path.of(fixture.mavenProject().getBuild().getDirectory(), "classes")
                : productionOutput.toPath());
    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.AnalysisOptions options =
        new ElisionAnalysisModel.AnalysisOptions(
            traceFiles.stream().map(Path::toFile).toList(),
            retainedArtifacts,
            List.of(),
            completeOutput,
            null,
            new ElisionAnalysisModel.CompletenessOptions(false, true, false, true),
            new ElisionAnalysisModel.TrimOptions(
                trimJars,
                List.of(),
                false,
                passThroughArtifacts,
                false,
                1,
                mrjarStrategy,
                producerResolution),
            new ElisionAnalysisModel.DynamicRootOptions(true),
            null,
            closedWorld);
    final ElisionAnalysisModel.PreparedAnalysis prepared =
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

  private File completeProductionClasses(final Fixture fixture, final Path output)
      throws IOException {
    final Path seedClass = output.resolve("fixture/Seed.class");
    Files.createDirectories(seedClass.getParent());
    Files.write(seedClass, ClosureFixtureCompileCache.seedClassBytes());
    fixture.mavenProject().getBuild().setOutputDirectory(output.toString());
    return output.toFile();
  }

  /** Runs the isolated effective output engine without changing Maven project views. */
  TrimResult trimEffective(final ServiceOperation operation)
      throws IOException, MojoFailureException {
    return MavenDependencyTrimmer.trimEffectiveOutputs(
        operation.service().finishAnalysis(operation.prepared()));
  }

  /** Writes one trace root using the native trace file format. */
  static Path trace(final Path directory, final String className) throws IOException {
    Files.createDirectories(directory);
    final Path file = directory.resolve("runtime.lst");
    Files.writeString(file, className + "\n");
    return file;
  }

  record ServiceOperation(
      MavenElisionService service, ElisionAnalysisModel.PreparedAnalysis prepared) {}
}
