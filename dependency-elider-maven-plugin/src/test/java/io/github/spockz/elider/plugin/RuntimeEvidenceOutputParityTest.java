/* WHY: Verifies Analyze predicts the descriptor and MRJAR outputs that Elide publishes. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Compares Analyze predictions with actual descriptor and archive transformations. */
final class RuntimeEvidenceOutputParityTest extends MavenDependencyTrimmerInMemoryClosureSupport {
  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* default */ RuntimeEvidenceOutputParityTest() {
    super();
  }

  @Test
  void analyzePredictionMatchesAppliedDescriptorAndRetainedArtifactViews() throws Exception {
    final Fixture fixture = fixture(false);
    final Path apiJar =
        RuntimeEvidenceArchiveFixture.compileJar(
            temporaryDirectory,
            "provider-api.jar",
            Map.of(
                "fixture/service/Spi.java",
                "package fixture.service; public interface Spi { String tier(); }"),
            null,
            11);
    final Path upperProviderJar =
        RuntimeEvidenceArchiveFixture.compileJar(
            temporaryDirectory,
            "upper-provider.jar",
            Map.of(
                "fixture/service/Provider.java",
                "package fixture.service; public class Provider implements Spi { "
                    + "public Provider() {} public String tier() { return \"upper\"; } }"),
            apiJar,
            17);
    final Path deadProviderJar =
        RuntimeEvidenceArchiveFixture.compileJar(
            temporaryDirectory,
            "dead-provider.jar",
            Map.of(
                "fixture/service/DeadProvider.java",
                "package fixture.service; public class DeadProvider implements Spi { "
                    + "public DeadProvider() {} public String tier() { return \"dead\"; } }"),
            apiJar,
            11);
    final Path descriptorOwner =
        RuntimeEvidenceArchiveFixture.mergedJar(
            fixture.snapshot("a").filePath(),
            apiJar,
            temporaryDirectory.resolve("descriptor-owner.jar"),
            Map.of(
                "META-INF/services/fixture.service.Spi",
                "fixture.service.Provider\n"
                    + "fixture.service.DeadProvider\n"
                    + "external.Provider\n"),
            null);
    final Path passThroughProvider =
        RuntimeEvidenceArchiveFixture.mergedJar(
            fixture.snapshot("b").filePath(),
            upperProviderJar,
            temporaryDirectory.resolve("pass-through-provider.jar"),
            Map.of(),
            "META-INF/versions/17/");
    final Path deadProviderInput =
        RuntimeEvidenceArchiveFixture.mergedJar(
            fixture.snapshot("c").filePath(),
            deadProviderJar,
            temporaryDirectory.resolve("dead-provider-input.jar"),
            Map.of(),
            null);
    final Artifact artifactA = fixture.artifacts().get(0);
    final Artifact artifactB = fixture.artifacts().get(1);
    final Artifact artifactC = fixture.artifacts().get(2);
    artifactA.setFile(descriptorOwner.toFile());
    artifactB.setFile(passThroughProvider.toFile());
    artifactC.setFile(deadProviderInput.toFile());
    fixture.mavenProject().setArtifacts(Set.copyOf(fixture.artifacts()));
    fixture.mavenProject().getProperties().setProperty("maven.compiler.release", "11");
    final Set<ArtifactCoordinate> inputCoordinates =
        fixture.artifacts().stream()
            .map(MavenArtifactInventory::toCoordinate)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    final Path trace = temporaryDirectory.resolve("service-parity.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final List<String> trimRoots = List.of("fixture.service.Spi", "closure/c/Leaf");

    final Path analyzeReport = temporaryDirectory.resolve("service-analyze-report.json");
    final Path analyzeSummary = temporaryDirectory.resolve("service-analyze-summary.json");
    final Path elideReport = temporaryDirectory.resolve("service-elide-report.json");
    final Path elideSummary = temporaryDirectory.resolve("service-elide-summary.json");
    final MavenElisionReportSnapshot prediction =
        analyze(fixture, trace, trimRoots, analyzeReport, analyzeSummary);
    final MavenElisionReportSnapshot applied =
        elide(fixture, trace, trimRoots, elideReport, elideSummary);
    final Set<ArtifactCoordinate> appliedViews =
        fixture.mavenProject().getArtifacts().stream()
            .map(MavenArtifactInventory::toCoordinate)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    final Path appliedRoot = RuntimeEvidenceGoalFixture.artifactPath(artifactA);
    final Path appliedPassThroughProvider = RuntimeEvidenceGoalFixture.artifactPath(artifactB);
    final Path appliedDeadProvider = RuntimeEvidenceGoalFixture.artifactPath(artifactC);
    final java.io.File appliedRootFile = appliedRoot.toFile();
    final URL appliedRootUrl = RuntimeEvidenceGoalFixture.archiveUrl(appliedRoot);
    final URL appliedProviderUrl =
        RuntimeEvidenceGoalFixture.archiveUrl(appliedPassThroughProvider);
    final Set<String> predictionTrimmed =
        prediction.trimmedArtifacts().stream()
            .map(MavenElisionReportSnapshot.TrimmedArtifact::coordinate)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    final Set<String> appliedTrimmed =
        applied.trimmedArtifacts().stream()
            .map(MavenElisionReportSnapshot.TrimmedArtifact::coordinate)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    final Map<String, List<ServiceDescriptorChange>> predictedDescriptorChanges =
        descriptorChangesByCoordinate(prediction);
    final Map<String, List<ServiceDescriptorChange>> appliedDescriptorChanges =
        descriptorChangesByCoordinate(applied);
    final Set<String> predictedDrops =
        prediction.droppedArtifacts().stream()
            .map(MavenElisionReportSnapshot.DroppedArtifact::coordinate)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    final Set<ArtifactCoordinate> predictedRetained =
        inputCoordinates.stream()
            .filter(coordinate -> !predictedDrops.contains(coordinate.toString()))
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    final Set<String> plannedProviderClasses =
        prediction.trimmedArtifacts().stream()
            .flatMap(value -> value.plannedClasses().stream())
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    final byte[] descriptorBytes;
    final String descriptorText;
    final Set<String> appliedRootEntries;
    try (JarFile output = new JarFile(appliedRootFile)) {
      appliedRootEntries =
          output.stream()
              .map(JarEntry::getName)
              .collect(java.util.stream.Collectors.toUnmodifiableSet());
      descriptorBytes =
          output
              .getInputStream(output.getJarEntry("META-INF/services/fixture.service.Spi"))
              .readAllBytes();
    }
    descriptorText = new String(descriptorBytes, java.nio.charset.StandardCharsets.UTF_8);
    final Object loadedProvider;
    try (URLClassLoader loader =
        new URLClassLoader(new URL[] {appliedRootUrl, appliedProviderUrl})) {
      final Class<?> serviceType = loader.loadClass("fixture.service.Spi");
      loadedProvider = ServiceLoader.load(serviceType, loader).findFirst().orElseThrow();
    }

    final int prunedClasses =
        applied.trimmedArtifacts().stream()
            .filter(artifact -> artifact.coordinate().contains("fixture:a:jar:1.0"))
            .mapToInt(MavenElisionReportSnapshot.TrimmedArtifact::programClassesPruned)
            .findFirst()
            .orElseThrow();
    assertAll(
        "Analyze predicts the same provider pruning and retained views that Elide publishes",
        () -> assertThat(prediction.mode()).isEqualTo(MavenElisionReportSnapshot.Mode.ANALYSIS),
        () -> assertThat(applied.mode()).isEqualTo(MavenElisionReportSnapshot.Mode.APPLIED),
        () -> assertThat(appliedViews).containsExactlyInAnyOrderElementsOf(predictedRetained),
        () -> assertThat(appliedRoot).isNotEqualTo(descriptorOwner),
        () -> assertThat(appliedPassThroughProvider).isEqualTo(passThroughProvider),
        () -> assertThat(appliedDeadProvider).isNotEqualTo(deadProviderInput),
        () -> assertThat(predictionTrimmed).containsExactlyInAnyOrderElementsOf(appliedTrimmed),
        () ->
            assertThat(appliedDescriptorChanges)
                .containsExactlyInAnyOrderEntriesOf(predictedDescriptorChanges),
        () ->
            assertThat(appliedDescriptorChanges.get("fixture:a:jar:1.0 (compile)").toString())
                .contains("META-INF/services/fixture.service.Spi", "REPLACED"),
        () ->
            assertEquals(
                0, prunedClasses, "The descriptor owner is rewritten without pruning classes"),
        () -> assertThat(plannedProviderClasses).contains("fixture.service.DeadProvider"),
        () ->
            assertThat(descriptorText)
                .contains("fixture.service.Provider", "external.Provider")
                .doesNotContain("fixture.service.DeadProvider"),
        () ->
            assertThat(
                    appliedRootEntries.stream()
                        .filter(name -> name.startsWith("META-INF/versions/"))
                        .filter(name -> name.contains("META-INF/services/")))
                .isEmpty(),
        () -> assertThat(loadedProvider.getClass().getName()).isEqualTo("fixture.service.Provider"),
        () ->
            assertThat(loadedProvider.getClass().getMethod("tier").invoke(loadedProvider))
                .isEqualTo("upper"));
  }

  private static Map<String, List<ServiceDescriptorChange>> descriptorChangesByCoordinate(
      final MavenElisionReportSnapshot snapshot) {
    return snapshot.trimmedArtifacts().stream()
        .collect(
            java.util.stream.Collectors.toUnmodifiableMap(
                MavenElisionReportSnapshot.TrimmedArtifact::coordinate,
                MavenElisionReportSnapshot.TrimmedArtifact::serviceDescriptorChanges));
  }

  private static MavenElisionReportSnapshot analyze(
      final Fixture fixture,
      final Path trace,
      final List<String> trimRoots,
      final Path report,
      final Path summary)
      throws ReflectiveOperationException,
          IOException,
          MojoExecutionException,
          MojoFailureException {
    final AnalyzeMojo mojo = new AnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(
        mojo, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession session = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(session, fixture);
    AnalyzeMojoTestFieldSupport.set(mojo, RuntimeEvidenceGoalFixture.SESSION_FIELD, session);
    configureGoal(mojo, trace, trimRoots, report);
    AnalyzeMojoTestFieldSupport.set(mojo, "analysisSummaryFile", summary.toFile());
    mojo.execute();
    return MavenElisionReportWriter.read(summary);
  }

  private static MavenElisionReportSnapshot elide(
      final Fixture fixture,
      final Path trace,
      final List<String> trimRoots,
      final Path report,
      final Path summary)
      throws ReflectiveOperationException,
          IOException,
          MojoExecutionException,
          MojoFailureException {
    final ElideMojo mojo = new ElideMojo();
    AnalyzeMojoTestFieldSupport.set(
        mojo, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession session = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(session, fixture);
    AnalyzeMojoTestFieldSupport.set(mojo, RuntimeEvidenceGoalFixture.SESSION_FIELD, session);
    configureGoal(mojo, trace, trimRoots, report);
    AnalyzeMojoTestFieldSupport.set(mojo, "summaryFile", summary.toFile());
    mojo.execute();
    return MavenElisionReportWriter.read(summary);
  }

  private static void configureGoal(
      final Object mojo, final Path trace, final List<String> trimRoots, final Path report)
      throws ReflectiveOperationException {
    AnalyzeMojoTestFieldSupport.set(
        mojo, RuntimeEvidenceGoalFixture.TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(mojo, "trimRoots", trimRoots);
    AnalyzeMojoTestFieldSupport.set(
        mojo, "mrjarStrategy", MavenDependencyTrimmer.MRJAR_PASS_THROUGH);
    AnalyzeMojoTestFieldSupport.set(mojo, "conservativeServiceLoaderRoots", false);
    AnalyzeMojoTestFieldSupport.set(mojo, "reportFile", report.toFile());
  }
}
