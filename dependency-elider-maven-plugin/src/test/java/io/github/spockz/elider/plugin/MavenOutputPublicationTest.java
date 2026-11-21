// WHY: Proves per-output replacement, ownership cleanup, and proof-gated publication behavior.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.HexDigest;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.model.PluginManagement;
import org.apache.maven.model.Resource;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformationContext;
import org.eclipse.aether.collection.DependencyGraphTransformer;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.CouplingBetweenObjects",
  "PMD.ExcessiveImports",
  "PMD.GodClass",
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter",
  "PMD.TooManyMethods",
  "checkstyle:AbbreviationAsWordInName"
})
final class MavenOutputPublicationTest {
  private static final String SCHEMA_FIELD = "schemaVersion";
  private static final String OUTPUTS_FIELD = "outputs";
  private static final String UNSUPPORTED_SCHEMA =
      "Unsupported generated output manifest schema version";

  private static final String PREVIOUS_GENERATED_OPENVEX = "previous generated OpenVEX";

  private static final String LOOKUP_METHOD = "lookup";

  private static final ObjectMapper JSON = new ObjectMapper();

  @TempDir Path temporaryDirectory;

  @Test
  void publishesPreconditionEvidenceFromOneRetainedInventoryWithoutTrimRecords() throws Exception {
    final Fixture fixture = fixture("eligible", false, false);
    configure(fixture, true);

    fixture.mojo().execute();

    assertThat(artifactFile(fixture.affected())).isEqualTo(fixture.affectedJar());
    final JsonNode sbom = JSON.readTree(fixture.sbom().toFile());
    final JsonNode affectedComponent = component(sbom, "affected");
    final String sha256 = HexDigest.sha256(fixture.affectedJar());
    assertThat(affectedComponent.path("hashes").get(0).path("content").asText()).isEqualTo(sha256);
    final JsonNode vulnerability = sbom.path("vulnerabilities").get(0);
    assertThat(vulnerability.path("analysis").path("state").asText()).isEqualTo("not_affected");
    assertThat(vulnerability.path("analysis").path("justification").asText())
        .isEqualTo("requires_dependency");

    final JsonNode openVex = JSON.readTree(fixture.vex().toFile());
    final JsonNode statement = openVex.path("statements").get(0);
    final JsonNode subcomponent = statement.path("products").get(0).path("subcomponents").get(0);
    assertThat(statement.path("status").asText()).isEqualTo("not_affected");
    assertThat(statement.has("justification")).isFalse();
    assertThat(subcomponent.path("identifiers").path("purl").asText())
        .contains("org.example/affected@1.0");
    assertThat(subcomponent.path("hashes").path("sha-256").asText()).isEqualTo(sha256);
    final MavenElisionReportSnapshot report = MavenElisionReportWriter.read(fixture.summary());
    assertThat(report.genericFindings())
        .singleElement()
        .satisfies(
            finding -> {
              assertThat(finding.vulnerabilityId()).isEqualTo("CVE-2026-12345");
              assertThat(finding.candidate().toId()).isEqualTo("org.example:affected:jar:1.0");
              assertThat(finding.outcome())
                  .isEqualTo(GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT);
              assertThat(finding.effectivePrerequisites())
                  .containsExactly(
                      new io.github.spockz.elider.model.PrerequisiteClaim(
                          "org.example:prerequisite", "org.example.prerequisite.EntryPoint"));
            });
    assertThat(report.trimmedArtifacts()).isEmpty();
  }

  @Test
  void analyzeGoalPredictsPrerequisitesAbsentWithoutEmittingVexOrSbomOnDisk() throws Exception {
    final Fixture fixture = fixture("analyze-non-emission", false, false);
    fixture.session().getRequest().setGoals(List.of("clean", "process-classes"));
    final Plugin plugin = new Plugin();
    plugin.setGroupId("io.github.spockz");
    plugin.setArtifactId("dependency-elider-maven-plugin");
    final org.apache.maven.plugin.MojoExecution execution =
        new org.apache.maven.plugin.MojoExecution(plugin, "analyze", "process-classes-binding");
    execution.setLifecyclePhase("process-classes");
    set(execution, "source", org.apache.maven.plugin.MojoExecution.Source.LIFECYCLE);
    final AnalyzeMojo analyzeMojo = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    set(analyzeMojo, "mojoExecution", execution);
    set(analyzeMojo, "project", fixture.project());
    set(analyzeMojo, "session", fixture.session());
    set(analyzeMojo, "projectDependenciesResolver", publicationResolver(fixture.project()));
    set(analyzeMojo, "traceFiles", List.of(fixture.trace().toFile()));
    set(analyzeMojo, "trimJars", true);
    set(analyzeMojo, "trimSkipArtifacts", List.of("org.example:affected:1.0"));
    set(analyzeMojo, "reportFile", fixture.classUsage().toFile());
    set(analyzeMojo, "analysisSummaryFile", fixture.summary().toFile());
    set(analyzeMojo, "cveCacheDirectory", fixture.basedir().resolve("cache").toFile());
    set(analyzeMojo, "osvSnapshotUri", null);
    set(analyzeMojo, "cveListGitUri", null);
    set(analyzeMojo, "preconditionClassPathComplete", true);
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-12345");
    mapping.setGroupId("org.example");
    mapping.setArtifactId("affected");
    mapping.setVersion("1.0");
    mapping.setVersionRangeSpec("[1.0]");
    mapping.setAssertsAffected(true);
    mapping.setConfidenceLevel("HIGH");
    mapping.setRequiresDependency("org.example:prerequisite");
    mapping.setRequiresClass("org.example.prerequisite.EntryPoint");
    set(analyzeMojo, "vulnerabilityMappings", List.of(mapping));

    analyzeMojo.execute();

    final MavenElisionReportSnapshot report = MavenElisionReportWriter.read(fixture.summary());
    assertAll(
        "Analyze predicts PREREQUISITES_ABSENT without emitting VEX or SBOM files",
        () -> assertThat(report.mode()).isEqualTo(MavenElisionReportSnapshot.Mode.ANALYSIS),
        () ->
            assertThat(report.genericFindings())
                .singleElement()
                .satisfies(
                    finding ->
                        assertThat(finding.outcome())
                            .isEqualTo(GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT)),
        () -> assertThat(fixture.vex()).doesNotExist(),
        () -> assertThat(fixture.sbom()).doesNotExist(),
        () -> assertThat(fixture.baselineSbom()).doesNotExist());
  }

  @Test
  void trimOffStillPublishesVerifiedReportsAndOwnershipWithoutReplacingRetainedJars()
      throws Exception {
    final Fixture fixture = fixture("verified-trim-off", false, false);
    final Artifact droppedPrerequisite = addDroppedPrerequisite(fixture);
    configure(fixture, true);
    set(fixture.mojo(), "trimJars", false);
    set(fixture.mojo(), "closedWorld", true);
    final byte[] affectedBytes = Files.readAllBytes(fixture.affectedJar());
    final Path originalAffectedFile = artifactFile(fixture.affected());
    fixture.mojo().execute();

    final Path ownership = MavenGeneratedOutputs.Paths.manifestPath(fixture.project());
    assertAll(
        "trim-off still publishes verified output from the final Maven artifact view",
        () -> assertThat(fixture.classUsage()).isRegularFile(),
        () -> assertThat(fixture.summary()).isRegularFile(),
        () -> assertThat(fixture.sbom()).isRegularFile(),
        () -> assertThat(fixture.baselineSbom()).isRegularFile(),
        () -> assertThat(fixture.vex()).isRegularFile(),
        () -> assertThat(ownership).isRegularFile(),
        () ->
            assertThat(JSON.readTree(fixture.sbom().toFile()).findValuesAsText("name"))
                .doesNotContain("prerequisite"),
        () ->
            assertThat(JSON.readTree(fixture.baselineSbom().toFile()).findValuesAsText("name"))
                .contains("prerequisite"),
        () -> assertThat(fixture.project().getArtifacts()).doesNotContain(droppedPrerequisite),
        () -> assertThat(artifactFile(fixture.affected())).isEqualTo(originalAffectedFile),
        () -> assertThat(Files.readAllBytes(fixture.affectedJar())).containsExactly(affectedBytes));
  }

  @Test
  void trimOffSecondExecutionDoesNotReuseFirstExecutionTrimRecords() throws Exception {
    final Fixture fixture = fixture("trim-off-no-prior-trim-state", false, false);
    configure(fixture, false);
    set(fixture.mojo(), "closedWorld", true);
    set(fixture.mojo(), "trimSkipArtifacts", List.of());
    writeJar(fixture.affectedJar(), "sample/Keep", "sample/Unused");
    final String inputDigest = HexDigest.sha256(fixture.affectedJar());

    fixture.mojo().execute();

    final MavenElisionReportSnapshot first = MavenElisionReportWriter.read(fixture.summary());
    final Path firstOutput = fixture.affected().getFile().toPath();
    final String firstOutputDigest = HexDigest.sha256(firstOutput);
    assertThat(first.trimmedArtifacts()).isNotEmpty();
    assertThat(firstOutput).isNotEqualTo(fixture.affectedJar());
    assertThat(firstOutputDigest).isNotEqualTo(inputDigest);
    set(fixture.mojo(), "trimJars", false);

    fixture.mojo().execute();

    final MavenElisionReportSnapshot second = MavenElisionReportWriter.read(fixture.summary());
    assertAll(
        "second output reflects its current no-trim analysis rather than earlier staged records",
        () -> assertThat(second.trimmedArtifacts()).isEmpty(),
        () ->
            assertThat(second.genericFindings())
                .singleElement()
                .satisfies(
                    finding -> {
                      assertThat(finding.outcome())
                          .isEqualTo(GenericFindingAssessment.Outcome.NO_PROOF);
                      assertThat(finding.prerequisiteProof()).isEmpty();
                    }),
        () -> assertThat(fixture.affected().getFile().toPath()).isEqualTo(firstOutput),
        () -> assertThat(HexDigest.sha256(firstOutput)).isEqualTo(firstOutputDigest));
  }

  @Test
  void oneReportReplacementIsAtomicAndWriteFailuresPropagate() throws Exception {
    final Path successDirectory = Files.createDirectories(temporaryDirectory.resolve("atomic"));
    final Path report = successDirectory.resolve("report.json");
    Files.writeString(report, "previous report");

    MavenClassUsageReportWriter.write(report, new ClassUsageReport(List.of()), Optional.empty());

    assertAll(
        "one report is replaced without leaving temporary siblings",
        () -> assertThat(JSON.readTree(report.toFile()).path(SCHEMA_FIELD).asInt()).isEqualTo(1),
        () -> assertThat(directoryEntries(successDirectory)).containsExactly(report));

    final Path failureDirectory = Files.createDirectories(temporaryDirectory.resolve("failed"));
    final Path directoryTarget = Files.createDirectory(failureDirectory.resolve("report.json"));
    assertThatThrownBy(
            () ->
                MavenClassUsageReportWriter.write(
                    directoryTarget, new ClassUsageReport(List.of()), Optional.empty()))
        .isInstanceOf(IOException.class);
    assertAll(
        "a failed replacement preserves the prior target and removes its temporary file",
        () ->
            Assertions.assertTrue(Files.isDirectory(directoryTarget), "Target remains a directory"),
        () -> assertThat(directoryEntries(directoryTarget)).isEmpty(),
        () -> assertThat(directoryEntries(failureDirectory)).containsExactly(directoryTarget));
  }

  @Test
  void partialFileWriteFailurePreservesPriorBytesAndRemovesSiblingTemporaryFile() throws Exception {
    final Path directory = Files.createDirectories(temporaryDirectory.resolve("partial-write"));
    final Path target = directory.resolve("summary.json");
    Files.writeString(target, "prior bytes");
    final AtomicReference<Path> temporary = new AtomicReference<>();

    assertThatThrownBy(
            () ->
                MavenGeneratedOutputs.writeAtomically(
                    target,
                    stage -> {
                      temporary.set(stage);
                      Files.writeString(stage, "partial new bytes");
                      throw new IOException("injected mid-write failure");
                    }))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("injected mid-write failure");

    assertAll(
        "failed single-file writes keep prior content and clean up their sibling temp",
        () -> assertThat(Optional.ofNullable(temporary.get())).isPresent(),
        () ->
            assertThat(Optional.ofNullable(temporary.get()).map(Path::getParent))
                .contains(directory),
        () ->
            Assertions.assertFalse(
                Optional.ofNullable(temporary.get()).map(Files::exists).orElse(false),
                "Failed temporary output is removed"),
        () -> assertThat(target).hasContent("prior bytes"),
        () -> assertThat(directoryEntries(directory)).containsExactly(target));
  }

  @Test
  void retainedCoordinateOrCompiledApplicationClassBlocksPreconditionPublication()
      throws Exception {
    final Fixture retainedCoordinate = fixture("retained-coordinate", true, false);
    configure(retainedCoordinate, true);
    set(retainedCoordinate.mojo(), "trimJars", false);
    retainedCoordinate.mojo().execute();
    assertThat(retainedCoordinate.vex()).doesNotExist();
    assertThat(prerequisiteFindings(MavenElisionReportWriter.read(retainedCoordinate.summary())))
        .isEmpty();

    final Fixture compiledProvider = fixture("compiled-provider", false, true);
    configure(compiledProvider, true);
    set(compiledProvider.mojo(), "trimJars", false);
    compiledProvider.mojo().execute();
    assertThat(compiledProvider.vex()).doesNotExist();
    assertThat(prerequisiteFindings(MavenElisionReportWriter.read(compiledProvider.summary())))
        .isEmpty();
  }

  @Test
  void trimOffAlternateDependencyAndResourceProvidersBlockPhysicalProof() throws Exception {
    assertAll(
        "alternate dependency and application resource providers remain physical blockers",
        () ->
            assertTrimOffDoesNotPublishProofForAlternateDependency(
                fixture("trim-off-alternate-provider", false, false)),
        () ->
            assertTrimOffDoesNotPublishProofForApplicationResource(
                fixture("trim-off-resource-provider", false, false)));
  }

  private void assertTrimOffDoesNotPublishProofForAlternateDependency(final Fixture fixture)
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    configure(fixture, true);
    set(fixture.mojo(), "trimJars", false);
    final Path alternateJar = fixture.basedir().resolve("alternate-provider.jar");
    writeJar(alternateJar, "org/example/prerequisite/EntryPoint", "sample/AlternateKeep");
    addArtifact(fixture, runtimeArtifact("alternate-provider", alternateJar));
    Files.writeString(fixture.trace(), "sample.Keep\nsample.AlternateKeep\n");

    fixture.mojo().execute();

    assertThat(fixture.vex()).doesNotExist();
    assertThat(prerequisiteFindings(MavenElisionReportWriter.read(fixture.summary()))).isEmpty();
  }

  private void assertTrimOffDoesNotPublishProofForApplicationResource(final Fixture fixture)
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    configure(fixture, true);
    set(fixture.mojo(), "trimJars", false);
    final Path classResource =
        fixture.resourceRoot().resolve("org/example/prerequisite/EntryPoint.class");
    Files.createDirectories(classResource.getParent());
    Files.write(classResource, classBytes("org/example/prerequisite/EntryPoint"));

    fixture.mojo().execute();

    assertThat(fixture.vex()).doesNotExist();
    assertThat(prerequisiteFindings(MavenElisionReportWriter.read(fixture.summary()))).isEmpty();
  }

  private static void addArtifact(final Fixture fixture, final Artifact artifact) {
    final Set<Artifact> artifacts = new LinkedHashSet<>(fixture.project().getArtifacts());
    artifacts.add(artifact);
    fixture.project().setArtifacts(artifacts);
    fixture.project().setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    capturePlannerGraph(fixture.project(), fixture.session().getRepositorySession());
  }

  @Test
  void trimOffCleansOnlyUnchangedOwnedStaleVexAndWarnsForModifiedOrUnownedFiles() throws Exception {
    final Fixture owned = fixture("trim-off-owned-stale-vex", false, false);
    configure(owned, false);
    set(owned.mojo(), "trimJars", false);
    writeVex(owned.vex(), PREVIOUS_GENERATED_OPENVEX);
    MavenGeneratedOutputs.record(owned.project(), List.of(owned.vex()));
    owned.mojo().execute();

    final JsonNode ownership =
        JSON.readTree(MavenGeneratedOutputs.Paths.manifestPath(owned.project()).toFile());

    final Fixture modified = fixture("trim-off-modified-stale-vex", false, false);
    configure(modified, false);
    set(modified.mojo(), "trimJars", false);
    writeVex(modified.vex(), PREVIOUS_GENERATED_OPENVEX);
    MavenGeneratedOutputs.record(modified.project(), List.of(modified.vex()));
    writeVex(modified.vex(), "user modified OpenVEX");
    final RecordingMavenLog modifiedLog = new RecordingMavenLog();
    modified.mojo().setLog(modifiedLog);
    modified.mojo().execute();

    final Fixture unowned = fixture("trim-off-unowned-stale-vex", false, false);
    configure(unowned, false);
    set(unowned.mojo(), "trimJars", false);
    writeVex(unowned.vex(), "user-owned OpenVEX");
    final RecordingMavenLog unownedLog = new RecordingMavenLog();
    unowned.mojo().setLog(unownedLog);
    unowned.mojo().execute();

    assertAll(
        "trim-off applies the same ownership-aware stale OpenVEX policy",
        () -> assertThat(owned.vex()).doesNotExist(),
        () ->
            assertThat(ownership.path(OUTPUTS_FIELD).findValuesAsText("path"))
                .doesNotContain(owned.vex().toAbsolutePath().normalize().toString()),
        () -> assertThat(modified.vex()).hasContent("user modified OpenVEX"),
        () ->
            assertThat(modifiedLog.warnings())
                .anyMatch(message -> message.contains("Preserving OpenVEX output")),
        () -> assertThat(unowned.vex()).hasContent("user-owned OpenVEX"),
        () ->
            assertThat(unownedLog.warnings())
                .anyMatch(message -> message.contains("Preserving OpenVEX output")));
  }

  @Test
  void trimOffRejectsOutputCollisionsWithOriginalArchivesBeforeWritingReports() throws Exception {
    final Fixture fixture = fixture("trim-off-output-archive-collision", false, false);
    configure(fixture, true);
    set(fixture.mojo(), "trimJars", false);
    set(fixture.mojo(), "sbomFile", fixture.affectedJar().toFile());
    final byte[] archiveBytes = Files.readAllBytes(fixture.affectedJar());
    Files.writeString(fixture.classUsage(), "prior class usage");
    Files.writeString(fixture.summary(), "prior summary");

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(org.apache.maven.plugin.MojoFailureException.class)
        .hasMessageContaining("collides with an artifact file");

    assertAll(
        "invalid output paths are rejected before report or archive writes",
        () -> assertThat(fixture.classUsage()).hasContent("prior class usage"),
        () -> assertThat(fixture.summary()).hasContent("prior summary"),
        () -> assertThat(Files.readAllBytes(fixture.affectedJar())).containsExactly(archiveBytes));
  }

  @Test
  void trimOffRejectsOutputCollisionsBeforeWritingReports() throws Exception {
    final Fixture fixture = fixture("trim-off-output-output-collision", false, false);
    configure(fixture, false);
    set(fixture.mojo(), "trimJars", false);
    set(fixture.mojo(), "sbomFile", fixture.summary().toFile());
    Files.writeString(fixture.classUsage(), "prior class usage");
    Files.writeString(fixture.summary(), "prior summary");

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(org.apache.maven.plugin.MojoFailureException.class)
        .hasMessageContaining("Duplicate output target path");

    assertAll(
        "output collisions leave existing reports untouched",
        () -> assertThat(fixture.classUsage()).hasContent("prior class usage"),
        () -> assertThat(fixture.summary()).hasContent("prior summary"));
  }

  @Test
  void incompleteInventorySuppressesProofAndDoesNotEmitOpenVex() throws Exception {
    final Fixture fixture = fixture("incomplete", false, false);
    configure(fixture, true);
    addUnknownGenerator(fixture, "process-classes");

    fixture.mojo().execute();

    assertThat(fixture.vex()).doesNotExist();
    assertThat(prerequisiteFindings(MavenElisionReportWriter.read(fixture.summary()))).isEmpty();
  }

  @Test
  void trimOffPublishesReportsButSuppressesVexForOptOutAndIncompleteInventory() throws Exception {
    final Fixture optedOut = fixture("trim-off-proof-opt-out", false, false);
    configure(optedOut, false);
    set(optedOut.mojo(), "trimJars", false);
    optedOut.mojo().execute();

    final Fixture incomplete = fixture("trim-off-incomplete-proof", false, false);
    configure(incomplete, true);
    set(incomplete.mojo(), "trimJars", false);
    addUnknownGenerator(incomplete, "process-classes");
    incomplete.mojo().execute();

    assertAll(
        "trim-off report generation does not relax physical proof requirements",
        () -> assertThat(optedOut.summary()).isRegularFile(),
        () -> assertThat(optedOut.sbom()).isRegularFile(),
        () -> assertThat(optedOut.vex()).doesNotExist(),
        () ->
            assertThat(prerequisiteFindings(MavenElisionReportWriter.read(optedOut.summary())))
                .isEmpty(),
        () -> assertThat(incomplete.summary()).isRegularFile(),
        () -> assertThat(incomplete.sbom()).isRegularFile(),
        () -> assertThat(incomplete.vex()).doesNotExist(),
        () ->
            assertThat(prerequisiteFindings(MavenElisionReportWriter.read(incomplete.summary())))
                .isEmpty());
  }

  @Test
  void sessionCompilerOverrideSuppressesPreconditionPublication() throws Exception {
    final Fixture fixture = fixture("compiler-override", false, false);
    configure(fixture, true);
    fixture.session().getUserProperties().setProperty("maven.compiler.proc", "full");

    fixture.mojo().execute();

    assertThat(fixture.vex()).doesNotExist();
    assertThat(fixture.summary()).exists();
    assertThat(prerequisiteFindings(MavenElisionReportWriter.read(fixture.summary()))).isEmpty();
  }

  @Test
  void downstreamProviderGeneratorsSuppressPublicationWithoutFailingTheBuild() throws Exception {
    for (final String phase :
        List.of("generate-test-sources", "process-classes", "process-test-classes")) {
      final Fixture fixture = fixture("provider-generator-" + phase, false, false);
      configure(fixture, true);
      addUnknownGenerator(fixture, phase);

      fixture.mojo().execute();

      assertThat(fixture.vex()).doesNotExist();
      assertThat(prerequisiteFindings(MavenElisionReportWriter.read(fixture.summary()))).isEmpty();
    }
  }

  @Test
  void testCompileSourceRootOverrideDoesNotSuppressRuntimeProof() throws Exception {
    final Fixture fixture = fixture("test-compile-source-override", false, false);
    configure(fixture, true);
    final Plugin compiler = new Plugin();
    compiler.setGroupId("org.apache.maven.plugins");
    compiler.setArtifactId("maven-compiler-plugin");
    final PluginExecution execution = new PluginExecution();
    execution.setId("default-testCompile");
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom proc = new Xpp3Dom("proc");
    proc.setValue("none");
    configuration.addChild(proc);
    final Xpp3Dom testRoots = new Xpp3Dom("compileSourceRoots");
    testRoots.setValue(fixture.basedir().resolve("external-test-sources").toString());
    configuration.addChild(testRoots);
    execution.setConfiguration(configuration);
    compiler.addExecution(execution);
    fixture.project().getBuild().addPlugin(compiler);

    fixture.mojo().execute();

    assertThat(fixture.vex()).isRegularFile();
    assertThat(prerequisiteFindings(MavenElisionReportWriter.read(fixture.summary())))
        .singleElement()
        .satisfies(
            finding ->
                assertThat(finding.candidate().toId()).isEqualTo("org.example:affected:jar:1.0"));
  }

  @Test
  void defaultOptOutDeletesOnlyUnchangedOwnedVexAndPreservesModifiedOrUnownedFiles()
      throws Exception {
    final Fixture owned = fixture("owned-stale-vex", false, false);
    configure(owned, false);
    writeVex(owned.vex(), PREVIOUS_GENERATED_OPENVEX);
    MavenGeneratedOutputs.record(owned.project(), List.of(owned.vex()));
    owned.mojo().execute();
    assertThat(owned.vex()).doesNotExist();
    assertThat(prerequisiteFindings(MavenElisionReportWriter.read(owned.summary()))).isEmpty();
    final JsonNode updatedManifest =
        JSON.readTree(MavenGeneratedOutputs.Paths.manifestPath(owned.project()).toFile());
    assertThat(updatedManifest.path(SCHEMA_FIELD).asInt()).isEqualTo(1);
    assertThat(updatedManifest.path(OUTPUTS_FIELD).findValuesAsText("path"))
        .doesNotContain(owned.vex().toAbsolutePath().normalize().toString());

    final Fixture modified = fixture("modified-stale-vex", false, false);
    configure(modified, false);
    writeVex(modified.vex(), PREVIOUS_GENERATED_OPENVEX);
    MavenGeneratedOutputs.record(modified.project(), List.of(modified.vex()));
    writeVex(modified.vex(), "user modified OpenVEX");
    final RecordingMavenLog modifiedLog = new RecordingMavenLog();
    modified.mojo().setLog(modifiedLog);
    modified.mojo().execute();
    assertThat(modified.vex()).hasContent("user modified OpenVEX");
    assertThat(modifiedLog.warnings())
        .anyMatch(message -> message.contains("Preserving OpenVEX output"));

    final Fixture unowned = fixture("unowned-stale-vex", false, false);
    configure(unowned, false);
    writeVex(unowned.vex(), "user-owned OpenVEX");
    final RecordingMavenLog unownedLog = new RecordingMavenLog();
    unowned.mojo().setLog(unownedLog);
    unowned.mojo().execute();
    assertThat(unowned.vex()).hasContent("user-owned OpenVEX");
    assertThat(unownedLog.warnings())
        .anyMatch(message -> message.contains("Preserving OpenVEX output"));
  }

  @Test
  void generatedOutputRegistryRequiresSchemaVersionOneAndExactFields() throws Exception {
    final Fixture fixture = fixture("strict-ownership-registry", false, false);
    final Path registry = MavenGeneratedOutputs.Paths.manifestPath(fixture.project());
    Files.createDirectories(registry.getParent());
    final ObjectNode unsupportedVersion = JSON.createObjectNode();
    unsupportedVersion.put(SCHEMA_FIELD, 2);
    unsupportedVersion.putArray(OUTPUTS_FIELD);
    JSON.writeValue(registry.toFile(), unsupportedVersion);

    assertThatThrownBy(
            () ->
                MavenGeneratedOutputs.unchangedOwnedOutputDigest(fixture.project(), fixture.vex()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(UNSUPPORTED_SCHEMA);

    final ObjectNode malformedEntry = JSON.createObjectNode();
    malformedEntry.put(SCHEMA_FIELD, 1);
    malformedEntry.putArray(OUTPUTS_FIELD).addObject().put("path", fixture.vex().toString());
    JSON.writeValue(registry.toFile(), malformedEntry);
    assertThatThrownBy(
            () ->
                MavenGeneratedOutputs.unchangedOwnedOutputDigest(fixture.project(), fixture.vex()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Malformed generated output digest");
  }

  @Test
  void generatedOutputRegistryRejectsEveryUnsupportedSchemaV1Shape() throws Exception {
    final Fixture fixture = fixture("strict-ownership-registry-shapes", false, false);
    final Path registry = MavenGeneratedOutputs.Paths.manifestPath(fixture.project());
    Files.createDirectories(registry.getParent());
    final ObjectNode valid = registryDocument(fixture.vex());
    final ObjectNode unknownTop = valid.deepCopy();
    unknownTop.put("extra", true);
    final ObjectNode unknownEntry = valid.deepCopy();
    ((ObjectNode) unknownEntry.withArray(OUTPUTS_FIELD).get(0)).put("extra", true);
    final ObjectNode duplicatePaths = JSON.createObjectNode();
    duplicatePaths.put(SCHEMA_FIELD, 1);
    duplicatePaths
        .putArray(OUTPUTS_FIELD)
        .add(valid.get(OUTPUTS_FIELD).get(0).deepCopy())
        .add(valid.get(OUTPUTS_FIELD).get(0).deepCopy());
    final List<org.junit.jupiter.api.function.Executable> checks =
        List.of(
            () ->
                rejectsRegistry(
                    registry,
                    fixture,
                    JSON.writeValueAsString(unknownTop),
                    "Unsupported generated output registry field extra"),
            () ->
                rejectsRegistry(
                    registry,
                    fixture,
                    JSON.writeValueAsString(unknownEntry),
                    "Unsupported generated output registry field extra"),
            () ->
                rejectsRegistry(
                    registry,
                    fixture,
                    "{\"schemaVersion\":1,\"schemaVersion\":1,\"outputs\":[]}",
                    "Duplicate field 'schemaVersion'"),
            () ->
                rejectsRegistry(
                    registry,
                    fixture,
                    JSON.writeValueAsString(duplicatePaths),
                    "Duplicate generated output registry path"),
            () ->
                rejectsRegistry(
                    registry,
                    fixture,
                    "{\"schemaVersion\":1,\"outputs\":[]} {}",
                    "Trailing data in generated output registry"),
            () -> rejectsRegistry(registry, fixture, "{\"outputs\":[]}", UNSUPPORTED_SCHEMA),
            () ->
                rejectsRegistry(
                    registry,
                    fixture,
                    "{\"schemaVersion\":\"1\",\"outputs\":[]}",
                    UNSUPPORTED_SCHEMA),
            () ->
                rejectsRegistry(
                    registry,
                    fixture,
                    "{\"schemaVersion\":4294967297,\"outputs\":[]}",
                    UNSUPPORTED_SCHEMA));
    assertAll("schema-v1 registry rejects malformed or unsupported data", checks);
  }

  private static ObjectNode registryDocument(final Path output) {
    final ObjectNode document = JSON.createObjectNode();
    document.put(SCHEMA_FIELD, 1);
    document
        .putArray(OUTPUTS_FIELD)
        .addObject()
        .put("path", output.toAbsolutePath().normalize().toString())
        .put("sha256", "0".repeat(64));
    return document;
  }

  private static void rejectsRegistry(
      final Path registry, final Fixture fixture, final String json, final String diagnostic)
      throws IOException {
    Files.writeString(registry, json);
    assertThatThrownBy(
            () ->
                MavenGeneratedOutputs.unchangedOwnedOutputDigest(fixture.project(), fixture.vex()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(diagnostic);
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static Path artifactFile(final Artifact artifact) {
    return artifact.getFile().toPath();
  }

  private Fixture fixture(
      final String name, final boolean retainedCoordinate, final boolean compiledProvider)
      throws IOException {
    final Path basedir = temporaryDirectory.resolve(name);
    final ProjectRoots roots = createProjectRoots(basedir);
    writeCompiledProvider(roots.productionOutput(), compiledProvider);
    final ArtifactSet artifactSet = createArtifacts(basedir, retainedCoordinate);
    final MavenProject project = createProject(basedir, roots, artifactSet.artifacts());
    final MavenSession session = newSession(project);
    final ElideMojo mojo = newMojo(session);
    final Path buildDirectory = basedir.resolve("target");
    final Path trace = basedir.resolve("runtime.lst");
    writeTrace(trace, retainedCoordinate);
    return new Fixture(
        project,
        session,
        mojo,
        artifactSet.affected(),
        basedir,
        artifactSet.affectedJar(),
        roots.sourceRoot(),
        roots.resourceRoot(),
        buildDirectory.resolve("class-usage.json"),
        buildDirectory.resolve("summary.json"),
        buildDirectory.resolve("sbom.json"),
        buildDirectory.resolve("baseline-sbom.json"),
        buildDirectory.resolve("dependency-elider.openvex.json"),
        trace,
        retainedCoordinate);
  }

  private static ProjectRoots createProjectRoots(final Path basedir) throws IOException {
    final ProjectRoots roots =
        new ProjectRoots(
            basedir.resolve("src/main/java"),
            basedir.resolve("src/test/java"),
            basedir.resolve("target/classes"),
            basedir.resolve("target/test-classes"),
            basedir.resolve("src/main/resources"),
            basedir.resolve("src/test/resources"));
    Files.createDirectories(roots.sourceRoot());
    Files.createDirectories(roots.testSourceRoot());
    Files.createDirectories(roots.productionOutput());
    Files.createDirectories(roots.testOutput());
    Files.createDirectories(roots.resourceRoot());
    Files.createDirectories(roots.testResourceRoot());
    return roots;
  }

  private static void writeCompiledProvider(final Path productionOutput, final boolean enabled)
      throws IOException {
    if (!enabled) {
      return;
    }
    final String className = "org/example/prerequisite/EntryPoint";
    final Path classFile = productionOutput.resolve(className + ".class");
    Files.createDirectories(classFile.getParent());
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);
    writer.visitEnd();
    Files.write(classFile, writer.toByteArray());
  }

  private static ArtifactSet createArtifacts(final Path basedir, final boolean retainPrerequisite)
      throws IOException {
    final Path affectedJar = basedir.resolve("affected.jar");
    writeJar(affectedJar, "sample/Keep", null);
    final Artifact affected = runtimeArtifact("affected", affectedJar);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(affected));
    if (retainPrerequisite) {
      final Path prerequisiteJar = basedir.resolve("prerequisite.jar");
      writeJar(prerequisiteJar, "org/example/prerequisite/EntryPoint", null);
      artifacts.add(runtimeArtifact("prerequisite", prerequisiteJar));
    }
    return new ArtifactSet(affected, affectedJar, artifacts);
  }

  private static MavenProject createProject(
      final Path basedir, final ProjectRoots roots, final Set<Artifact> artifacts) {
    final MavenProject project = new MavenProject();
    project.setFile(basedir.resolve("pom.xml").toFile());
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setName("Consumer");
    project.setPackaging("jar");
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.getProperties().setProperty("maven.compiler.release", "21");
    project.getProperties().setProperty("maven.compiler.proc", "none");
    project.addCompileSourceRoot(roots.sourceRoot().toString());
    project.addTestCompileSourceRoot(roots.testSourceRoot().toString());
    project.setBuild(createBuild(basedir, roots));
    addResources(project, roots);
    return project;
  }

  private static Build createBuild(final Path basedir, final ProjectRoots roots) {
    final Build build = new Build();
    build.setDirectory(basedir.resolve("target").toString());
    build.setOutputDirectory(roots.productionOutput().toString());
    build.setTestOutputDirectory(roots.testOutput().toString());
    final Plugin compiler = new Plugin();
    compiler.setGroupId("org.apache.maven.plugins");
    compiler.setArtifactId("maven-compiler-plugin");
    compiler.setVersion("3.13.0");
    final PluginManagement management = new PluginManagement();
    management.addPlugin(compiler);
    management.addPlugin(surefirePlugin());
    build.setPluginManagement(management);
    final Plugin surefire = surefirePlugin();
    final PluginExecution defaultTest = new PluginExecution();
    defaultTest.setId("default-test");
    defaultTest.setPhase("test");
    defaultTest.setGoals(List.of("test"));
    surefire.addExecution(defaultTest);
    build.addPlugin(surefire);
    return build;
  }

  private static void addResources(final MavenProject project, final ProjectRoots roots) {
    final Resource productionResources = new Resource();
    productionResources.setDirectory(roots.resourceRoot().toString());
    project.addResource(productionResources);
    final Resource testResources = new Resource();
    testResources.setDirectory(roots.testResourceRoot().toString());
    project.addTestResource(testResources);
  }

  private static void writeTrace(final Path trace, final boolean retainedCoordinate)
      throws IOException {
    final String content =
        retainedCoordinate ? "sample.Keep\norg.example.prerequisite.EntryPoint\n" : "sample.Keep\n";
    Files.writeString(trace, content);
  }

  private void configure(final Fixture fixture, final boolean proofEnabled) {
    final ElideMojo mojo = fixture.mojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", fixture.project());
    set(mojo, "traceFiles", List.of(fixture.trace().toFile()));
    set(mojo, "trimJars", true);
    final List<String> passThrough =
        fixture.retainedCoordinate()
            ? List.of("org.example:affected:1.0", "org.example:prerequisite:1.0")
            : List.of("org.example:affected:1.0");
    set(mojo, "trimSkipArtifacts", passThrough);
    set(mojo, "reportFile", fixture.classUsage().toFile());
    set(mojo, "summaryFile", fixture.summary().toFile());
    set(mojo, "sbomFile", fixture.sbom().toFile());
    set(mojo, "baselineSbomFile", fixture.baselineSbom().toFile());
    set(mojo, "vexFile", fixture.vex().toFile());
    set(mojo, "cveCacheDirectory", fixture.basedir().resolve("cache").toFile());
    set(mojo, "osvSnapshotUri", null);
    set(mojo, "cveListGitUri", null);
    if (proofEnabled) {
      set(mojo, "preconditionClassPathComplete", true);
    }
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-12345");
    mapping.setGroupId("org.example");
    mapping.setArtifactId("affected");
    mapping.setVersion("1.0");
    mapping.setVersionRangeSpec("[1.0]");
    mapping.setAssertsAffected(true);
    mapping.setConfidenceLevel("HIGH");
    mapping.setRequiresDependency("org.example:prerequisite");
    mapping.setRequiresClass("org.example.prerequisite.EntryPoint");
    set(mojo, "vulnerabilityMappings", List.of(mapping));
  }

  private static List<Path> directoryEntries(final Path directory) throws IOException {
    try (java.util.stream.Stream<Path> entries = Files.list(directory)) {
      return entries.sorted().toList();
    }
  }

  private static void writeVex(final Path path, final String content) throws IOException {
    Files.createDirectories(path.getParent());
    Files.writeString(path, content);
  }

  private static JsonNode component(final JsonNode sbom, final String artifactId) {
    for (final JsonNode component : sbom.path("components")) {
      if (artifactId.equals(component.path("name").asText())) {
        return component;
      }
    }
    throw new AssertionError("Missing SBOM component " + artifactId);
  }

  private static byte[] classBytes(final String internalName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static void writeJar(final Path path, final String internalName, final String secondClass)
      throws IOException {
    Files.createDirectories(path.getParent());
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      addClass(output, internalName);
      if (secondClass != null) {
        addClass(output, secondClass);
      }
    }
  }

  private static void addClass(final JarOutputStream output, final String internalName)
      throws IOException {
    output.putNextEntry(new JarEntry(internalName + ".class"));
    output.write(classBytes(internalName));
    output.closeEntry();
  }

  private static Artifact runtimeArtifact(final String artifactId, final Path jar) {
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            "1.0",
            "runtime",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(jar.toFile());
    return artifact;
  }

  private Artifact addDroppedPrerequisite(final Fixture fixture) throws IOException {
    final Path jar = fixture.basedir().resolve("prerequisite.jar");
    writeJar(jar, "org/example/prerequisite/EntryPoint", null);
    final Artifact prerequisite = runtimeArtifact("prerequisite", jar);
    addArtifact(fixture, prerequisite);
    return prerequisite;
  }

  private static void addUnknownGenerator(final Fixture fixture, final String phase) {
    final Plugin generator = new Plugin();
    generator.setGroupId("com.example");
    generator.setArtifactId("provider-generator");
    final PluginExecution execution = new PluginExecution();
    execution.setId("generate-providers");
    execution.setPhase(phase);
    execution.setGoals(List.of("generate"));
    generator.addExecution(execution);
    fixture.project().getBuild().addPlugin(generator);
  }

  private static MavenSession newSession(final MavenProject project) {
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setGoals(List.of("clean", "verify"));
    request.setBaseDirectory(project.getBasedir());
    final DefaultRepositorySystemSession baseSession = new DefaultRepositorySystemSession();
    final org.eclipse.aether.RepositorySystemSession capturedSession =
        new EliderMediatedGraphCaptureDecorator().decorate(project, baseSession);
    baseSession
        .getData()
        .set(
            ResolverArtifactPlanPublisher.SESSION_DATA_KEY,
            ResolverArtifactPlanStore.empty()
                .withPlan(EliderMediatedGraphCaptureDecoratorTestSupport.emptyPlan(project))
                .toPayload());
    capturePlannerGraph(project, capturedSession);
    final MavenSession session = new MavenSession(testContainer(), capturedSession, request, null);
    session.setCurrentProject(project);
    session.getUserProperties().setProperty("skipTests", "true");
    return session;
  }

  private static void capturePlannerGraph(
      final MavenProject project,
      final org.eclipse.aether.RepositorySystemSession repositorySession) {
    final DependencyNode root =
        new DefaultDependencyNode(
            new Dependency(
                new org.eclipse.aether.artifact.DefaultArtifact(
                    project.getGroupId(), project.getArtifactId(), "", "pom", project.getVersion()),
                "",
                false));
    root.setChildren(
        project.getArtifacts().stream()
            .map(artifact -> publicationDependency(project, artifact.getArtifactId()))
            .map(DefaultDependencyNode::new)
            .map(node -> (DependencyNode) node)
            .toList());
    try {
      repositorySession
          .getDependencyGraphTransformer()
          .transformGraph(
              root,
              (DependencyGraphTransformationContext)
                  Proxy.newProxyInstance(
                      Thread.currentThread().getContextClassLoader(),
                      new Class<?>[] {DependencyGraphTransformationContext.class},
                      (proxy, method, arguments) ->
                          "getSession".equals(method.getName()) ? repositorySession : null));
    } catch (final org.eclipse.aether.RepositoryException exception) {
      throw new IllegalStateException("Planner graph capture failed", exception);
    }
  }

  private static Plugin surefirePlugin() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId("org.apache.maven.plugins");
    plugin.setArtifactId("maven-surefire-plugin");
    plugin.setVersion("3.5.2");
    return plugin;
  }

  private static ElideMojo newMojo(final MavenSession session) {
    final ElideMojo mojo = ExplicitRuntimeMojoTestSupport.newElideMojo();
    set(mojo, "session", session);
    set(mojo, "projectDependenciesResolver", publicationResolver(session.getCurrentProject()));
    return mojo;
  }

  private static ProjectDependenciesResolver publicationResolver(final MavenProject project) {
    return resolutionRequest -> {
      final org.eclipse.aether.RepositorySystemSession repositorySession =
          resolutionRequest.getRepositorySession();
      final List<Dependency> dependencies =
          project.getArtifacts().stream()
              .map(artifact -> publicationDependency(project, artifact.getArtifactId()))
              .toList();
      final DependencyNode root =
          new DefaultDependencyNode(
              new Dependency(
                  new org.eclipse.aether.artifact.DefaultArtifact(
                      "org.example", "consumer", "", "pom", "1.0"),
                  "",
                  false));
      root.setChildren(
          dependencies.stream().<DependencyNode>map(DefaultDependencyNode::new).toList());
      final DependencyGraphTransformer transformer =
          repositorySession.getDependencyGraphTransformer();
      final DependencyNode graph;
      try {
        graph =
            transformer.transformGraph(
                root,
                (DependencyGraphTransformationContext)
                    Proxy.newProxyInstance(
                        Thread.currentThread().getContextClassLoader(),
                        new Class<?>[] {DependencyGraphTransformationContext.class},
                        (proxy, method, arguments) ->
                            "getSession".equals(method.getName()) ? repositorySession : null));
      } catch (final org.eclipse.aether.RepositoryException exception) {
        throw new IllegalStateException("Publication graph capture failed", exception);
      }
      return (DependencyResolutionResult)
          Proxy.newProxyInstance(
              Thread.currentThread().getContextClassLoader(),
              new Class<?>[] {DependencyResolutionResult.class},
              (proxy, method, arguments) ->
                  switch (method.getName()) {
                    case "getCollectionErrors",
                        "getUnresolvedDependencies",
                        "getResolutionErrors" ->
                        List.of();
                    case "getResolvedDependencies" -> dependencies;
                    case "getDependencyGraph" -> graph;
                    case null, default -> null;
                  });
    };
  }

  private static Dependency publicationDependency(
      final MavenProject project, final String artifactId) {
    final Artifact projectArtifact =
        project.getArtifacts().stream()
            .filter(artifact -> artifactId.equals(artifact.getArtifactId()))
            .findFirst()
            .orElseThrow();
    final org.eclipse.aether.artifact.Artifact artifact =
        new org.eclipse.aether.artifact.DefaultArtifact(
            "org.example",
            artifactId,
            "",
            "jar",
            "1.0",
            java.util.Map.of(),
            projectArtifact.getFile());
    return new Dependency(artifact, "runtime", false);
  }

  private static List<GenericFindingAssessment> prerequisiteFindings(
      final MavenElisionReportSnapshot report) {
    return report.genericFindings().stream()
        .filter(
            finding -> finding.outcome() == GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT)
        .toList();
  }

  @SuppressWarnings("PMD.UseProperClassLoader")
  private static PlexusContainer testContainer() {
    return (PlexusContainer)
        Proxy.newProxyInstance(
            PlexusContainer.class.getClassLoader(),
            new Class<?>[] {PlexusContainer.class},
            (proxy, method, arguments) -> {
              if (LOOKUP_METHOD.equals(method.getName())) {
                return new org.apache.maven.toolchain.DefaultToolchainManager();
              }
              return null;
            });
  }

  private static void set(final Object target, final String name, final Object value) {
    try {
      AnalyzeMojoTestFieldSupport.set(target, name, value);
    } catch (final ReflectiveOperationException exception) {
      throw new IllegalStateException("Cannot set fixture field " + name, exception);
    }
  }

  private record ProjectRoots(
      Path sourceRoot,
      Path testSourceRoot,
      Path productionOutput,
      Path testOutput,
      Path resourceRoot,
      Path testResourceRoot) {}

  private record ArtifactSet(Artifact affected, Path affectedJar, Set<Artifact> artifacts) {}

  private record Fixture(
      MavenProject project,
      MavenSession session,
      ElideMojo mojo,
      Artifact affected,
      Path basedir,
      Path affectedJar,
      Path sourceRoot,
      Path resourceRoot,
      Path classUsage,
      Path summary,
      Path sbom,
      Path baselineSbom,
      Path vex,
      Path trace,
      boolean retainedCoordinate) {}
}
