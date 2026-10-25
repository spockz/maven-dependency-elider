// WHY: Applies the trace-grounded artifact decision early enough for later Maven phases to use it.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.metadata.CycloneDxSbomGenerator;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

/** Removes unobserved dependency JARs from Maven's in-memory artifact views. */
@Mojo(
    name = "elide",
    defaultPhase = LifecyclePhase.INITIALIZE,
    requiresDependencyResolution = ResolutionScope.TEST,
    threadSafe = true)
@SuppressWarnings({
  "PMD.CyclomaticComplexity",
  "PMD.CollapsibleIfStatements",
  "PMD.GuardLogStatement",
  "PMD.UseConcurrentHashMap",
  "PMD.UseExplicitTypes",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.LawOfDemeter"
})
public final class ElideMojo extends AbstractMojo {
  /** Maven project whose artifact views are pruned. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Maven session used to detect an externally selected compiler toolchain. */
  @Parameter(defaultValue = "${session}", readonly = true)
  private MavenSession session;

  /** User assertion that all production/generated sources exist before INITIALIZE. */
  @Parameter(property = "elide.sourceRootsComplete", defaultValue = "false")
  private boolean sourceRootsComplete;

  /** Enables per-JAR trimming for retained dependency archives. */
  @Parameter(property = "elide.trimJars", defaultValue = "false")
  private boolean trimJars;

  /** Additional class names that must remain available for dynamic loading. */
  @Parameter(property = "elide.trimRoots")
  private List<String> trimRoots;

  /** Explicit runtime evidence used when the goal is active. */
  @Parameter(property = "elide.traceFiles")
  private List<File> traceFiles;

  /** Global artifact identities that must remain in the build. */
  @Parameter(property = "elide.excludedArtifacts")
  private List<String> excludedArtifacts;

  /** Optional production class output for static references. */
  @Parameter(property = "elide.productionOutput")
  private File productionOutput;

  /** Structured report path, defaulting to the Maven build directory. */
  @Parameter(
      property = "elide.reportFile",
      defaultValue = "${project.build.directory}/dependency-elider-class-usage.json")
  private File reportFile;

  /** SBOM output generated when trimming is enabled. */
  @Parameter(
      property = "elide.sbomFile",
      defaultValue = "${project.build.directory}/dependency-elider-sbom.cdx.json")
  private File sbomFile;

  /** Maven switch that skips analysis and mutation. */
  @Parameter(property = "elide.skip", defaultValue = "false")
  private boolean skip;

  /** Analyzes runtime evidence and applies the validated retained-artifact plan. */
  @Override
  public void execute() throws MojoFailureException {
    if (skip) {
      return;
    }
    try {
      final MavenElisionService service = new MavenElisionService();
      final MavenElisionService.Analysis analysis =
          service.analyze(
              project,
              traceFiles,
              excludedArtifacts,
              productionOutput,
              session,
              sourceRootsComplete,
              trimJars,
              trimRoots == null ? List.of() : trimRoots);
      final MavenElisionService.ApplyPlan plan = service.plan(project, analysis);
      MavenClassUsageReportWriter.write(
          reportFile.toPath(), analysis.classUsageReport(), analysis.bytecodeScan());
      if (trimJars) {
        writeSbom(plan, analysis);
      }
      applyTrimRecords(plan, analysis.trimRecords());
      project.setArtifacts(new LinkedHashSet<>(plan.resolvedArtifacts()));
      if (plan.directArtifactsPresent()) {
        project.setDependencyArtifacts(new LinkedHashSet<>(plan.directArtifacts()));
      }
      if (trimJars) {
        if (analysis.trimCacheHits() > 0) {
          final double milliseconds = analysis.maximumTrimCacheHitNanos() / 1_000_000.0;
          getLog()
              .info(
                  "  JAR trim cache: "
                      + analysis.trimCacheHits()
                      + " hit(s), maximum validated hit "
                      + milliseconds
                      + " ms (target < 1.5 ms)");
        }
      }
      ElisionSummary.report(getLog(), analysis.decision(), analysis.resolvedSnapshots().size());
      if (getLog().isInfoEnabled()) {
        getLog().info("  Class usage report: " + reportFile.toPath().toAbsolutePath().normalize());
      }
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency elision failed: " + exception.getMessage(), exception);
    }
  }

  private static void applyTrimRecords(
      final MavenElisionService.ApplyPlan plan,
      final List<io.github.spockz.elider.trimmer.ArtifactTrimRecord> records)
      throws IOException {
    final java.util.Map<
            io.github.spockz.elider.model.ArtifactCoordinate,
            io.github.spockz.elider.trimmer.ArtifactTrimRecord>
        byCoordinate = new java.util.HashMap<>();
    for (final var record : records) {
      byCoordinate.put(record.coordinate(), record);
    }
    final Set<org.apache.maven.artifact.Artifact> all =
        new LinkedHashSet<>(plan.resolvedArtifacts());
    all.addAll(plan.directArtifacts());
    for (final org.apache.maven.artifact.Artifact artifact : all) {
      final var coordinate =
          new io.github.spockz.elider.model.ArtifactCoordinate(
              artifact.getGroupId(),
              artifact.getArtifactId(),
              artifact.getVersion(),
              artifact.getType(),
              artifact.getClassifier(),
              artifact.getScope());
      final var record = byCoordinate.get(coordinate);
      if (record != null) {
        if (artifact.getFile() == null
            || !artifact
                .getFile()
                .toPath()
                .toAbsolutePath()
                .normalize()
                .equals(record.originalPath())) {
          throw new IOException("Artifact path changed before applying trim: " + coordinate);
        }
        artifact.setFile(record.trimmedPath().toFile());
      }
    }
  }

  private void writeSbom(
      final MavenElisionService.ApplyPlan plan, final MavenElisionService.Analysis analysis)
      throws IOException {
    final List<ArtifactFileRef> inventory = new ArrayList<>();
    final java.util.Map<io.github.spockz.elider.model.ArtifactCoordinate, Path> trimmedPaths =
        new java.util.HashMap<>();
    for (final var record : analysis.trimRecords()) {
      trimmedPaths.put(record.coordinate(), record.trimmedPath());
    }
    for (final org.apache.maven.artifact.Artifact artifact : plan.resolvedArtifacts()) {
      if (artifact.getFile() != null) {
        final var coordinate =
            new io.github.spockz.elider.model.ArtifactCoordinate(
                artifact.getGroupId(),
                artifact.getArtifactId(),
                artifact.getVersion(),
                artifact.getType(),
                artifact.getClassifier(),
                artifact.getScope());
        final Path inventoryPath =
            trimmedPaths.getOrDefault(coordinate, artifact.getFile().toPath());
        inventory.add(ArtifactFileRef.fromPath(coordinate, inventoryPath));
      }
    }
    final String name = project.getName() == null ? project.getArtifactId() : project.getName();
    final CycloneDxSbomGenerator.RootIdentity root =
        new CycloneDxSbomGenerator.RootIdentity(
            project.getGroupId(), project.getArtifactId(), project.getVersion(), name);
    final CycloneDxSbomGenerator.DocumentMetadata metadata =
        new CycloneDxSbomGenerator.DocumentMetadata(
            "urn:uuid:" + UUID.randomUUID(),
            1,
            Instant.now(),
            "dependency-elider-maven-plugin",
            "0.1.0-SNAPSHOT");
    new CycloneDxSbomGenerator()
        .write(
            sbomFile.toPath(),
            root,
            inventory,
            analysis.decision(),
            metadata,
            analysis.trimRecords());
  }

  /** Creates a Mojo instance for Maven injection. */
  public ElideMojo() {
    super();
  }
}
