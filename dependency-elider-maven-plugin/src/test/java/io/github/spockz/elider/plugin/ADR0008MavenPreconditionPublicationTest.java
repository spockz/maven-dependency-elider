// WHY: Proves Maven publishes exact-class precondition evidence only through the shared inventory
// and rollback transaction.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.ToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** WHY: Groups publication and rollback cases around one shared fixture. */
@DisplayName("ADR-0008: Maven precondition publication and rollback")
@SuppressWarnings({
  "PMD.AvoidAccessibilityAlteration",
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CouplingBetweenObjects",
  "PMD.ExcessiveImports",
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts",
  "checkstyle:AbbreviationAsWordInName"
})
final class ADR0008MavenPreconditionPublicationTest {
  /** Private Mojo field used by the staging hook tests. */
  private static final String AFTER_STAGING_FIELD = "afterStaging";

  /** Previously generated VEX bytes preserved during rollback tests. */
  private static final String PREVIOUS_GENERATED_OPENVEX = "previous generated OpenVEX";

  /** Plexus lookup method name used by the test container proxy. */
  private static final String LOOKUP_METHOD = "lookup";

  /** JSON reader and writer for report assertions and staged-file tampering cases. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Isolated project and output root for each publication scenario. */
  @TempDir Path temporaryDirectory;

  @Test
  void publishesPreconditionEvidenceFromOneRetainedInventoryWithoutTrimRecords() throws Exception {
    final Fixture fixture = fixture("eligible", false, false);
    configure(fixture, true);

    fixture.mojo().execute();

    assertThat(artifactFile(fixture.affected())).isEqualTo(fixture.affectedJar());
    final JsonNode sbom = JSON.readTree(fixture.sbom().toFile());
    final JsonNode affectedComponent = component(sbom, "affected");
    final String sha256 = ArtifactFileDigest.sha256(fixture.affectedJar());
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
    assertThat(MavenElisionReportWriter.read(fixture.summary()).inactivePreconditionCves())
        .containsExactly(
            new MavenElisionReportSnapshot.CveFinding(
                "CVE-2026-12345", "org.example:affected:jar:1.0"));
    assertThat(MavenElisionReportWriter.read(fixture.summary()).trimmedArtifacts()).isEmpty();
  }

  @Test
  void retainedCoordinateOrApplicationSourceClassBlocksPreconditionPublication() throws Exception {
    final Fixture retainedCoordinate = fixture("retained-coordinate", true, false);
    configure(retainedCoordinate, true);
    retainedCoordinate.mojo().execute();
    assertThat(retainedCoordinate.vex()).doesNotExist();
    assertThat(
            MavenElisionReportWriter.read(retainedCoordinate.summary()).inactivePreconditionCves())
        .isEmpty();

    final Fixture sourceProvider = fixture("source-provider", false, true);
    configure(sourceProvider, true);
    sourceProvider.mojo().execute();
    assertThat(sourceProvider.vex()).doesNotExist();
    assertThat(MavenElisionReportWriter.read(sourceProvider.summary()).inactivePreconditionCves())
        .isEmpty();
  }

  @Test
  void incompleteInventorySuppressesProofAndDoesNotEmitOpenVex() throws Exception {
    final Fixture fixture = fixture("incomplete", false, false);
    Files.writeString(fixture.sourceRoot().resolve("Unknown.scala"), "class Unknown\n");
    configure(fixture, true);

    fixture.mojo().execute();

    assertThat(fixture.vex()).doesNotExist();
    assertThat(MavenElisionReportWriter.read(fixture.summary()).inactivePreconditionCves())
        .isEmpty();
  }

  @Test
  void sessionCompilerOverrideSuppressesPreconditionPublication() throws Exception {
    final Fixture fixture = fixture("compiler-override", false, false);
    configure(fixture, true);
    fixture.session().getUserProperties().setProperty("maven.compiler.proc", "full");

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("annotation processing to be disabled");

    assertThat(fixture.vex()).doesNotExist();
    assertThat(fixture.summary()).doesNotExist();
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
      assertThat(MavenElisionReportWriter.read(fixture.summary()).inactivePreconditionCves())
          .isEmpty();
    }
  }

  @Test
  void testCompileSourceRootOverrideSuppressesPreconditionPublication() throws Exception {
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

    assertThat(fixture.vex()).doesNotExist();
    assertThat(MavenElisionReportWriter.read(fixture.summary()).inactivePreconditionCves())
        .isEmpty();
  }

  @Test
  void providerMutationOrAdditionDuringStagingAbortsAllOutputPublication() throws Exception {
    for (final boolean addProvider : List.of(false, true)) {
      final Fixture fixture = fixture("provider-drift-" + addProvider, false, false);
      configure(fixture, true);
      final Path changedResource = fixture.resourceRoot().resolve("existing.bin");
      if (!addProvider) {
        Files.writeString(changedResource, "unchanged provider");
      }
      writePreviousOutputs(fixture);
      set(
          fixture.mojo(),
          AFTER_STAGING_FIELD,
          (MavenElisionOutputPublisher.AfterStaging)
              () -> {
                if (addProvider) {
                  Files.write(changedResource, classBytes("late.Provider"));
                } else {
                  Files.writeString(changedResource, "mutated provider");
                }
              });

      assertThatThrownBy(fixture.mojo()::execute)
          .isInstanceOf(MojoFailureException.class)
          .hasMessageContaining("provider inventory changed");
      assertPreviousOutputs(fixture);
    }
  }

  @Test
  void outputTargetMutationDuringStagingAbortsBeforeInstallingAnyReport() throws Exception {
    final Fixture fixture = fixture("output-target-drift", false, false);
    configure(fixture, true);
    writePreviousOutputs(fixture);
    set(
        fixture.mojo(),
        AFTER_STAGING_FIELD,
        (MavenElisionOutputPublisher.AfterStaging)
            () -> Files.writeString(fixture.summary(), "concurrent summary update"));

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("provider inventory changed");

    assertThat(fixture.classUsage()).hasContent("old class usage");
    assertThat(fixture.summary()).hasContent("concurrent summary update");
    assertThat(fixture.sbom()).hasContent("old SBOM");
    assertThat(fixture.baselineSbom()).hasContent("old baseline SBOM");
    assertThat(fixture.vex()).hasContent("old OpenVEX");
  }

  @Test
  void validJsonStageTamperingAbortsAndRestoresPreviousOutputs() throws Exception {
    final Fixture fixture = fixture("valid-json-stage-tamper", false, false);
    configure(fixture, true);
    writePreviousOutputs(fixture);
    set(
        fixture.mojo(),
        AFTER_STAGING_FIELD,
        (MavenElisionOutputPublisher.AfterStaging)
            () -> {
              final ObjectNode changed =
                  (ObjectNode) JSON.readTree(stageFor(fixture.summary()).toFile());
              changed.put("tampered", true);
              JSON.writeValue(stageFor(fixture.summary()).toFile(), changed);
            });

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Staged output changed after staging");

    assertPreviousOutputs(fixture);
  }

  @Test
  void coordinatedManifestAndSbomStageTamperingStillAborts() throws Exception {
    final Fixture fixture = fixture("coordinated-stage-tamper", false, false);
    configure(fixture, true);
    writePreviousOutputs(fixture);
    set(
        fixture.mojo(),
        AFTER_STAGING_FIELD,
        (MavenElisionOutputPublisher.AfterStaging)
            () -> {
              final Path sbomStage = stageFor(fixture.sbom());
              final ObjectNode changedSbom = (ObjectNode) JSON.readTree(sbomStage.toFile());
              changedSbom.put("tampered", true);
              JSON.writeValue(sbomStage.toFile(), changedSbom);
              final String changedDigest = ArtifactFileDigest.sha256(sbomStage);

              final Path manifestStage =
                  stageFor(MavenGeneratedOutputs.manifestPath(fixture.project()));
              final ObjectNode manifest = (ObjectNode) JSON.readTree(manifestStage.toFile());
              final ArrayNode outputs = (ArrayNode) manifest.path("outputs");
              final Path sbomTarget = fixture.sbom().toAbsolutePath().normalize();
              boolean updatedSbomEntry = false;
              for (final JsonNode output : outputs) {
                final ObjectNode entry = (ObjectNode) output;
                if (Path.of(entry.path("path").asText())
                    .toAbsolutePath()
                    .normalize()
                    .equals(sbomTarget)) {
                  entry.put("sha256", changedDigest);
                  updatedSbomEntry = true;
                }
              }
              if (!updatedSbomEntry) {
                throw new IOException("SBOM stage was not recorded in generated-output manifest");
              }
              JSON.writeValue(manifestStage.toFile(), manifest);
            });

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Staged output changed after staging");

    assertPreviousOutputs(fixture);
  }

  @Test
  void defaultOptOutDeletesOnlyUnchangedOwnedVexAndPreservesModifiedOrUnownedFiles()
      throws Exception {
    final Fixture owned = fixture("owned-stale-vex", false, false);
    configure(owned, false);
    writeVex(owned.vex(), PREVIOUS_GENERATED_OPENVEX);
    MavenGeneratedOutputManifest.write(
        MavenGeneratedOutputs.manifestPath(owned.project()), List.of(owned.vex()));
    owned.mojo().execute();
    assertThat(owned.vex()).doesNotExist();
    assertThat(MavenElisionReportWriter.read(owned.summary()).inactivePreconditionCves()).isEmpty();

    final Fixture modified = fixture("modified-stale-vex", false, false);
    configure(modified, false);
    writeVex(modified.vex(), PREVIOUS_GENERATED_OPENVEX);
    MavenGeneratedOutputManifest.write(
        MavenGeneratedOutputs.manifestPath(modified.project()), List.of(modified.vex()));
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
  void resolverFailureAfterStaleVexDeletionRestoresPriorVexAndManifest() throws Exception {
    final Fixture fixture = fixture("rollback-stale-vex", false, false);
    configure(fixture, false);
    final Set<Artifact> originalArtifacts = new LinkedHashSet<>(fixture.project().getArtifacts());
    final Path resolvedOnlyJar = fixture.basedir().resolve("resolved-only.jar");
    writeJar(resolvedOnlyJar, "other/ResolvedOnly", null);
    final Artifact resolvedOnly = runtimeArtifact("resolved-only", resolvedOnlyJar);
    final Set<Artifact> originalResolvedArtifacts = new LinkedHashSet<>(originalArtifacts);
    originalResolvedArtifacts.add(resolvedOnly);
    fixture.project().setResolvedArtifacts(originalResolvedArtifacts);
    fixture.project().setArtifacts(new LinkedHashSet<>(originalArtifacts));
    writeVex(fixture.vex(), PREVIOUS_GENERATED_OPENVEX);
    final Path manifest = MavenGeneratedOutputs.manifestPath(fixture.project());
    MavenGeneratedOutputManifest.write(manifest, List.of(fixture.vex()));
    final byte[] priorManifest = Files.readAllBytes(manifest);
    set(
        fixture.mojo(),
        "planPublication",
        (ElideMojo.PlanPublication)
            (ignoredSession, ignoredProject, ignoredRecords, ignoredProjection) -> {
              throw new IOException("injected resolver publication failure");
            });

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("injected resolver publication failure");

    assertThat(fixture.vex()).hasContent(PREVIOUS_GENERATED_OPENVEX);
    assertThat(Files.readAllBytes(manifest)).isEqualTo(priorManifest);
    assertThat(fixture.project().getArtifacts()).containsExactlyElementsOf(originalArtifacts);
    assertThat(resolvedArtifactView(fixture.project()))
        .containsExactlyElementsOf(originalResolvedArtifacts);
  }

  private static Set<Artifact> resolvedArtifactView(final MavenProject project) {
    final MavenProject snapshot = project.clone();
    snapshot.setArtifactFilter(artifact -> true);
    snapshot.setArtifacts(null);
    return new LinkedHashSet<>(snapshot.getArtifacts());
  }

  @SuppressWarnings("PMD.LawOfDemeter") // Maven Artifact exposes its file through a File accessor.
  private static Path artifactFile(final Artifact artifact) {
    return artifact.getFile().toPath();
  }

  private Fixture fixture(
      final String name, final boolean retainedCoordinate, final boolean sourceProvider)
      throws IOException {
    final Path basedir = temporaryDirectory.resolve(name);
    final ProjectRoots roots = createProjectRoots(basedir);
    writeSourceProvider(roots.sourceRoot(), sourceProvider);
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

  private static void writeSourceProvider(final Path sourceRoot, final boolean enabled)
      throws IOException {
    if (!enabled) {
      return;
    }
    final Path source = sourceRoot.resolve("org/example/prerequisite/EntryPoint.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source, "package org.example.prerequisite; public final class EntryPoint {}\n");
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
    mapping.setConfidenceLevel("HIGH");
    mapping.setRequiresDependency("org.example:prerequisite");
    mapping.setRequiresClass("org.example.prerequisite.EntryPoint");
    set(mojo, "vulnerabilityMappings", List.of(mapping));
  }

  private void writePreviousOutputs(final Fixture fixture) throws IOException {
    Files.createDirectories(fixture.classUsage().getParent());
    Files.writeString(fixture.classUsage(), "old class usage");
    Files.writeString(fixture.summary(), "old summary");
    Files.writeString(fixture.sbom(), "old SBOM");
    Files.writeString(fixture.baselineSbom(), "old baseline SBOM");
    writeVex(fixture.vex(), "old OpenVEX");
  }

  private void assertPreviousOutputs(final Fixture fixture) throws IOException {
    assertThat(fixture.classUsage()).hasContent("old class usage");
    assertThat(fixture.summary()).hasContent("old summary");
    assertThat(fixture.sbom()).hasContent("old SBOM");
    assertThat(fixture.baselineSbom()).hasContent("old baseline SBOM");
    assertThat(fixture.vex()).hasContent("old OpenVEX");
  }

  private static void writeVex(final Path path, final String content) throws IOException {
    Files.createDirectories(path.getParent());
    Files.writeString(path, content);
  }

  private static Path stageFor(final Path target) throws IOException {
    final String prefix = "." + target.getFileName() + ".staged-";
    try (java.util.stream.Stream<Path> paths = Files.list(target.getParent())) {
      return paths
          .filter(path -> path.getFileName().toString().startsWith(prefix))
          .findFirst()
          .orElseThrow(() -> new IOException("Missing stage for output: " + target));
    }
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
    final MavenSession session = new MavenSession(testContainer(), request, null, project);
    session.getUserProperties().setProperty("skipTests", "true");
    return session;
  }

  private static Plugin surefirePlugin() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId("org.apache.maven.plugins");
    plugin.setArtifactId("maven-surefire-plugin");
    plugin.setVersion("3.5.2");
    return plugin;
  }

  private static ElideMojo newMojo(final MavenSession session) {
    final ElideMojo mojo = new ElideMojo();
    set(mojo, "session", session);
    return mojo;
  }

  @SuppressWarnings("PMD.UseProperClassLoader")
  private static PlexusContainer testContainer() {
    return (PlexusContainer)
        Proxy.newProxyInstance(
            PlexusContainer.class.getClassLoader(),
            new Class<?>[] {PlexusContainer.class},
            (proxy, method, arguments) -> {
              if (LOOKUP_METHOD.equals(method.getName())) {
                return Proxy.newProxyInstance(
                    ToolchainManager.class.getClassLoader(),
                    new Class<?>[] {ToolchainManager.class},
                    (manager, managerMethod, managerArguments) -> null);
              }
              return null;
            });
  }

  private static void set(final Object target, final String name, final Object value) {
    try {
      final Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      field.set(target, value);
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
