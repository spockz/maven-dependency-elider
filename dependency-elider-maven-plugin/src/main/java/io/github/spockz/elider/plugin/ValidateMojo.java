// WHY: Fails fast on invalid plugin configuration and input paths before compile runs.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;

/** Validates lightweight configuration in Maven's {@code validate} phase. */
@Mojo(
    name = "validate",
    defaultPhase = LifecyclePhase.VALIDATE,
    requiresDependencyResolution = ResolutionScope.NONE,
    threadSafe = true)
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
public final class ValidateMojo extends AbstractElisionMojo {
  /** Maven switch that skips validation along with elision. */
  @Parameter(property = "elide.skip", defaultValue = DEFAULT_FALSE)
  boolean skip;

  /** Explicit runtime evidence used when {@code elide} is active. */
  @Parameter(property = "elide.traceFiles")
  List<File> traceFiles;

  /** CycloneDX SBOM output generated for the elided dependency inventory. */
  @Parameter(
      property = "elide.sbomFile",
      defaultValue = "${project.build.directory}/dependency-elider-sbom.cdx.json")
  File sbomFile;

  /** Baseline inventory SBOM written before whole-artifact removal. */
  @Parameter(
      property = "elide.baselineSbomFile",
      defaultValue = "${project.build.directory}/baseline-sbom.cdx.json")
  File baselineSbomFile;

  /** Trim-mode OpenVEX output. */
  @Parameter(
      property = "elide.vexFile",
      defaultValue = "${project.build.directory}/dependency-elider.openvex.json")
  File vexFile;

  /** Persisted elision snapshot for {@code report}. */
  @Parameter(
      property = "elide.summaryFile",
      defaultValue = "${project.build.directory}/dependency-elider-report.json")
  File summaryFile;

  /** Creates a validate Mojo instance for Maven injection. */
  public ValidateMojo() {
    super();
  }

  /** Runs lightweight config and path checks without resolving dependencies. */
  @Override
  public void execute() throws MojoFailureException {
    if (skip) {
      return;
    }
    if (leafOnly && ReactorLeafModuleDetector.isIntermediateReactorModule(project, session)) {
      return;
    }
    MavenElideConfigurationValidation.validate(
        new MavenElideConfigurationValidation.Request(
            sourceRootsComplete,
            trimWorkers,
            mrjarStrategy,
            retainDuplicateClassOwners,
            trimDuplicateClassOwners,
            trimRoots,
            retainedArtifacts,
            trimSkipArtifacts,
            banishedDependencies,
            vulnerabilityMappingCatalogs,
            cveCacheTtlHours,
            osvSnapshotUri,
            cveListGitUri,
            snykApiBaseUri,
            vulnerabilityMappings,
            traceFiles,
            cveCacheDirectory,
            reportFile,
            MavenGeneratedOutputs.Paths.outputFile(
                sbomFile, project, "dependency-elider-sbom.cdx.json"),
            MavenGeneratedOutputs.Paths.outputFile(
                baselineSbomFile, project, "baseline-sbom.cdx.json"),
            MavenGeneratedOutputs.Paths.outputFile(
                vexFile, project, "dependency-elider.openvex.json"),
            summaryFile));
    if (trimJars) {
      // Emit any missing producer-identity warning early if trimming is enabled.
      sharedTrimOptions();
    }
  }
}
