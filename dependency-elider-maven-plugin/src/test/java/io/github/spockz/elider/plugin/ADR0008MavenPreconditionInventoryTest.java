// WHY: Verifies Maven inventory capture includes declared providers and rejects membership drift.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.model.PreconditionProof;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.model.Resource;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Verifies the captured precondition provider boundary. */
@DisplayName("ADR-0008: Maven precondition inventory completeness and freshness")
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.ExcessiveImports",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts",
  "checkstyle:AbbreviationAsWordInName"
})
final class ADR0008MavenPreconditionInventoryTest {
  /** Maven artifact type used by all provider fixtures. */
  private static final String JAR_TYPE = "jar";

  /** Shared failure text for stale provider snapshots. */
  private static final String INVENTORY_CHANGED = "provider inventory changed";

  /** Temporary project and archive files for provider inventory scenarios. */
  @TempDir Path temporaryDirectory;

  @Test
  void capturesProductionAndTestSourceClassesAndAllDeclaredFileRoots() throws IOException {
    final Fixture fixture = fixture();
    final Path productionSource =
        writeSource(
            fixture.productionSources(),
            "Main.java",
            "package app; public final class Main { static final class Nested {} }\n");
    final Path testSource =
        writeSource(
            fixture.testSources(), "TestOnly.java", "package test; public class TestOnly {}\n");
    final Path outputClass = fixture.productionOutput().resolve("compiled/Output.class");
    writeClass(outputClass, "compiled/Output");
    final Path testClass = fixture.testOutput().resolve("compiled/TestOutput.class");
    writeClass(testClass, "compiled/TestOutput");
    final Path resource = fixture.productionResources().resolve("renamed.bin");
    Files.createDirectories(resource.getParent());
    Files.write(resource, classBytes("resources/Hidden"));
    final Path testResource = fixture.testResources().resolve("test.data");
    Files.createDirectories(testResource.getParent());
    Files.writeString(testResource, "ordinary test resource");

    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(), fixture.plan(), fixture.analysis(), true, List.of());

    assertThat(snapshot.complete()).isTrue();
    assertThat(snapshot.classProviders().providers())
        .anySatisfy(
            provider -> {
              assertThat(provider.path()).isEqualTo(productionSource);
              assertThat(provider.kind()).isEqualTo(ProviderKind.APPLICATION_SOURCE_FILE);
              assertThat(provider.discoveredClassNames()).contains("app.Main", "app.Main$Nested");
            })
        .anySatisfy(
            provider -> {
              assertThat(provider.path()).isEqualTo(testSource);
              assertThat(provider.kind()).isEqualTo(ProviderKind.APPLICATION_SOURCE_FILE);
              assertThat(provider.discoveredClassNames()).contains("test.TestOnly");
            })
        .anySatisfy(
            provider -> {
              assertThat(provider.path()).isEqualTo(outputClass);
              assertThat(provider.kind()).isEqualTo(ProviderKind.APPLICATION_CLASS_FILE);
            })
        .anySatisfy(
            provider -> {
              assertThat(provider.path()).isEqualTo(testClass);
              assertThat(provider.kind()).isEqualTo(ProviderKind.APPLICATION_CLASS_FILE);
            })
        .anySatisfy(
            provider -> {
              assertThat(provider.path()).isEqualTo(resource);
              assertThat(provider.kind()).isEqualTo(ProviderKind.APPLICATION_RESOURCE_FILE);
            })
        .anySatisfy(
            provider -> {
              assertThat(provider.path()).isEqualTo(testResource);
              assertThat(provider.kind()).isEqualTo(ProviderKind.APPLICATION_RESOURCE_FILE);
            });
  }

  @Test
  void disabledPreconditionProofInventoryIsIncomplete() throws IOException {
    final Fixture fixture = fixture();
    writeSource(fixture.productionSources(), "Invalid.java", "class Invalid { syntax ??? }\n");

    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(), fixture.plan(), fixture.analysis(), false, List.of());

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail()).contains("opt-in is disabled");
  }

  @Test
  void missingRetainedArtifactFileProducesIncompleteProofInventory() throws IOException {
    final Fixture fixture = fixture();
    final Artifact retainedArtifact = fixture.plan().resolvedArtifacts().iterator().next();
    retainedArtifact.setFile(null);

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail()).contains("has no file");
  }

  @Test
  void revalidationRejectsAddedProviderAndChangedResourceBytes() throws IOException {
    final Fixture fixture = fixture();
    Files.createDirectories(fixture.productionResources());
    final Path resource = fixture.productionResources().resolve("first.dat");
    Files.writeString(resource, "ordinary resource");
    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);
    final Path added = fixture.testResources().resolve("added.bin");
    Files.createDirectories(added.getParent());
    Files.writeString(added, "new provider");

    assertThatThrownBy(
            () ->
                snapshot.verifyFresh(
                    fixture.project(), fixture.plan(), fixture.analysis(), List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(INVENTORY_CHANGED);

    Files.delete(added);
    Files.writeString(resource, "changed resource bytes");
    assertThatThrownBy(
            () ->
                snapshot.verifyFresh(
                    fixture.project(), fixture.plan(), fixture.analysis(), List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(INVENTORY_CHANGED);
  }

  @Test
  void revalidationRejectsChangedJavaSourceBytes() throws IOException {
    final Fixture fixture = fixture();
    final Path source =
        writeSource(
            fixture.productionSources(), "Snapshot.java", "package app; class Snapshot {}\n");
    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);
    Files.writeString(source, "package app; class Snapshot { static class Added {} }\n");

    assertThatThrownBy(
            () ->
                snapshot.verifyFresh(
                    fixture.project(), fixture.plan(), fixture.analysis(), List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(INVENTORY_CHANGED);
  }

  @Test
  void revalidationRejectsChangedRetainedArtifactAndMavenViewMembership() throws IOException {
    final Fixture fixture = fixture();
    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);
    Files.writeString(fixture.dependency(), "changed");

    assertThatThrownBy(
            () ->
                snapshot.verifyFresh(
                    fixture.project(), fixture.plan(), fixture.analysis(), List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(INVENTORY_CHANGED);

    final Fixture membershipFixture = fixture();
    final MavenPreconditionInventory.Snapshot membershipSnapshot = capture(membershipFixture);
    final Artifact addedArtifact =
        new DefaultArtifact(
            "org.example",
            "added",
            "1.0",
            "compile",
            JAR_TYPE,
            null,
            new DefaultArtifactHandler(JAR_TYPE));
    final Set<Artifact> changedArtifacts =
        new LinkedHashSet<>(membershipFixture.project().getArtifacts());
    changedArtifacts.add(addedArtifact);
    membershipFixture.project().setArtifacts(changedArtifacts);

    assertThatThrownBy(
            () ->
                membershipSnapshot.verifyFresh(
                    membershipFixture.project(),
                    membershipFixture.plan(),
                    membershipFixture.analysis(),
                    List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact view size changed");
  }

  @Test
  void lateRootPopulationInvalidatesTheInventorySnapshot() throws IOException {
    final Fixture fixture = fixture();
    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);
    Files.createDirectories(fixture.testResources());
    Files.writeString(fixture.testResources().resolve("late.txt"), "late resource");

    assertThatThrownBy(
            () ->
                snapshot.verifyFresh(
                    fixture.project(), fixture.plan(), fixture.analysis(), List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(INVENTORY_CHANGED);
  }

  @Test
  void indeterminateRootExistenceMakesInventoryIncomplete() throws IOException {
    assumeUnixEnvironment();
    final Fixture fixture = fixture();
    final Path unqueryableRoot = fixture.productionSources().resolve("x".repeat(300));
    Assumptions.assumeTrue(!Files.exists(unqueryableRoot, LinkOption.NOFOLLOW_LINKS));
    Assumptions.assumeTrue(!Files.notExists(unqueryableRoot, LinkOption.NOFOLLOW_LINKS));
    fixture.project().addCompileSourceRoot(unqueryableRoot.toString());

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail())
        .contains("Cannot determine declared Maven provider root state");
  }

  @Test
  void indeterminateStageExistenceMakesInventoryIncomplete() throws IOException {
    assumeUnixEnvironment();
    final Fixture fixture = fixture();
    Files.createDirectories(fixture.productionResources());
    final Path stage = fixture.productionResources().resolve("s".repeat(300));
    Assumptions.assumeTrue(!Files.exists(stage, LinkOption.NOFOLLOW_LINKS));
    Assumptions.assumeTrue(!Files.notExists(stage, LinkOption.NOFOLLOW_LINKS));

    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(), fixture.plan(), fixture.analysis(), true, List.of(), List.of(stage));

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail())
        .contains("Cannot determine generated output path state");
  }

  @Test
  void indeterminateOutputExistenceMakesInventoryIncomplete() throws IOException {
    assumeUnixEnvironment();
    final Fixture fixture = fixture();
    Files.createDirectories(fixture.productionResources());
    final Path output = fixture.productionResources().resolve("o".repeat(300));
    Assumptions.assumeTrue(!Files.exists(output, LinkOption.NOFOLLOW_LINKS));
    Assumptions.assumeTrue(!Files.notExists(output, LinkOption.NOFOLLOW_LINKS));

    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(), fixture.plan(), fixture.analysis(), true, List.of(output));

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail())
        .contains("Cannot determine generated output path state");
  }

  @Test
  void revalidationRejectsOutputTargetChangesAndValidatesOnlyKnownStagesAsGeneratedJson()
      throws IOException {
    final Fixture fixture = fixture();
    final Path target = fixture.productionResources().resolve("sbom.json");
    Files.createDirectories(target.getParent());
    Files.writeString(target, "{\"previous\":true}");
    final Path stage = fixture.productionResources().resolve(".sbom.json.staged-known");
    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(),
            fixture.plan(),
            fixture.analysis(),
            true,
            List.of(target),
            List.of(stage));
    Files.writeString(stage, "{\"schema\":1}");

    snapshot.verifyFresh(
        fixture.project(), fixture.plan(), fixture.analysis(), List.of(target), List.of(stage));
    assertThatThrownBy(
            () ->
                snapshot.verifyFresh(
                    fixture.project(),
                    fixture.plan(),
                    fixture.analysis(),
                    List.of(fixture.productionResources().resolve("other.json")),
                    List.of(stage)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("output targets changed");

    Files.write(stage, classBytes("generated/Unexpected"));
    assertThatThrownBy(
            () ->
                snapshot.verifyFresh(
                    fixture.project(),
                    fixture.plan(),
                    fixture.analysis(),
                    List.of(target),
                    List.of(stage)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("not valid JSON");
  }

  @Test
  void existingStagingPathMustBeValidatedBeforeItCanBeExcludedFromProviderRoots()
      throws IOException {
    final Fixture fixture = fixture();
    final Path stage = fixture.productionResources().resolve(".sbom.json.staged-known");
    Files.createDirectories(stage.getParent());
    Files.write(stage, classBytes("generated/Unexpected"));

    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(), fixture.plan(), fixture.analysis(), true, List.of(), List.of(stage));

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail()).contains("not valid JSON");
  }

  @Test
  void rawClassBytesAtAnOutputTargetRemainClassProviders() throws IOException {
    final Fixture fixture = fixture();
    assertThat(fixture.project().getResources()).hasSize(1);
    final Path outputTarget = fixture.productionResources().resolve("custom-report.json");
    Files.createDirectories(outputTarget.getParent());
    Files.write(outputTarget, classBytes("hidden/ShadedPrerequisite"));
    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(), fixture.plan(), fixture.analysis(), true, List.of(outputTarget));
    final VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            "CVE-2026-12345",
            fixture.coordinate(),
            "[1.0]",
            Set.of(),
            null,
            VulnerabilitySymbolMapping.ConfidenceLevel.HIGH,
            "org.example:missing-prerequisite",
            "hidden.ShadedPrerequisite");

    assertThat(snapshot.complete()).isTrue();
    assertThat(snapshot.classProviders().providers())
        .anySatisfy(provider -> assertThat(provider.path()).isEqualTo(outputTarget));
    assertThatThrownBy(() -> PreconditionProof.prove(mapping, snapshot.classProviders()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  void unknownSourceFileShapeMakesInventoryIncomplete() throws IOException {
    final Fixture fixture = fixture();
    Files.createDirectories(fixture.productionSources());
    Files.writeString(fixture.productionSources().resolve("generated.scala"), "class Unknown");

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail()).contains("Unsupported non-Java source");
  }

  @Test
  void localAndAnonymousJavaClassesMakeInventoryIncomplete() throws IOException {
    final Fixture fixture = fixture();
    writeSource(
        fixture.productionSources(),
        "LocalTypes.java",
        "package app; public class LocalTypes { void run() { class Local {} "
            + "Runnable r = new Runnable() { public void run() {} }; } }\n");

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail())
        .contains("Unsupported Java source declaration")
        .containsAnyOf("local classes", "anonymous classes");
  }

  @Test
  void enumSwitchCompilerGeneratedClassWithoutOutputMakesInventoryIncomplete() throws IOException {
    final Fixture fixture = fixture();
    writeSource(
        fixture.productionSources(),
        "Holder.java",
        "package app; enum Mode { A, B } "
            + "class Holder { int value(Mode mode) { return switch (mode) { "
            + "case A -> 1; case B -> 2; }; } }\n");
    final VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            "CVE-2026-12345",
            fixture.coordinate(),
            "[1.0]",
            Set.of(),
            null,
            VulnerabilitySymbolMapping.ConfidenceLevel.HIGH,
            "org.example:missing-prerequisite",
            "app.Holder$1");

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail()).contains("compiler-generated class providers");
    assertThatThrownBy(() -> PreconditionProof.prove(mapping, snapshot.classProviders()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void socketFilesMakeInventoryIncompleteInsteadOfBeingSkipped() throws IOException {
    assumeUnixEnvironment();
    final Fixture fixture = fixture();
    Files.createDirectories(fixture.productionResources());
    final Path socketPath = fixture.productionResources().resolve("provider.sock");

    try (ServerSocketChannel socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
      socket.bind(UnixDomainSocketAddress.of(socketPath));

      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

      assertThat(snapshot.complete()).isFalse();
      assertThat(snapshot.classProviders().detail()).contains("Unsupported filesystem entry");
    }
  }

  private MavenPreconditionInventory.Snapshot capture(final Fixture fixture) throws IOException {
    return MavenPreconditionInventory.capture(
        fixture.project(), fixture.plan(), fixture.analysis(), true, List.of());
  }

  private static void assumeUnixEnvironment() {
    final String operatingSystem = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    Assumptions.assumeTrue(operatingSystem.contains("linux") || operatingSystem.contains("mac"));
  }

  private Fixture fixture() throws IOException {
    final Path basedir = temporaryDirectory.resolve("project");
    Files.createDirectories(basedir);
    final Path sourceRoot = basedir.resolve("src/main/java");
    final Path testSourceRoot = basedir.resolve("src/test/java");
    final Path productionOutput = basedir.resolve("target/classes");
    final Path testOutput = basedir.resolve("target/test-classes");
    final Path productionResources = basedir.resolve("src/main/resources");
    final Path testResources = basedir.resolve("src/test/resources");
    Files.createDirectories(sourceRoot);
    final Path dependency = temporaryDirectory.resolve("affected.jar");
    writeJar(dependency);
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            "affected",
            "1.0",
            "compile",
            JAR_TYPE,
            null,
            new DefaultArtifactHandler(JAR_TYPE));
    artifact.setFile(dependency.toFile());
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(artifact));
    final MavenProject project = new MavenProject();
    project.setFile(basedir.resolve("pom.xml").toFile());
    project.setPackaging(JAR_TYPE);
    project.setArtifacts(artifacts);
    project.addCompileSourceRoot(sourceRoot.toString());
    project.addTestCompileSourceRoot(testSourceRoot.toString());
    final Build build = new Build();
    build.setDirectory(basedir.resolve("target").toString());
    build.setOutputDirectory(productionOutput.toString());
    build.setTestOutputDirectory(testOutput.toString());
    final Resource productionResource = new Resource();
    productionResource.setDirectory(productionResources.toString());
    final Resource testResource = new Resource();
    testResource.setDirectory(testResources.toString());
    project.setBuild(build);
    project.addResource(productionResource);
    project.addTestResource(testResource);
    final ArtifactCoordinate coordinate = MavenElisionService.toCoordinate(artifact);
    final MavenElisionService.Analysis analysis =
        new MavenElisionService.Analysis(
            MavenElisionService.snapshots(List.of(artifact)),
            false,
            List.of(),
            new io.github.spockz.elider.model.ElisionDecision(
                Set.of(), Set.of(coordinate), Map.of(), Map.of(), 0L));
    final MavenElisionService.ApplyPlan plan =
        new MavenElisionService.ApplyPlan(artifacts, false, Set.of());
    return new Fixture(
        project,
        analysis,
        plan,
        coordinate,
        dependency,
        sourceRoot,
        testSourceRoot,
        productionOutput,
        testOutput,
        productionResources,
        testResources);
  }

  private static Path writeSource(final Path root, final String name, final String source)
      throws IOException {
    Files.createDirectories(root);
    final Path file = root.resolve(name);
    Files.writeString(file, source);
    return file;
  }

  private static void writeJar(final Path path) throws IOException {
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      output.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
      output.write("Manifest-Version: 1.0\n\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
    }
  }

  private static void writeClass(final Path path, final String internalName) throws IOException {
    Files.createDirectories(path.getParent());
    Files.write(path, classBytes(internalName));
  }

  private static byte[] classBytes(final String internalName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private record Fixture(
      MavenProject project,
      MavenElisionService.Analysis analysis,
      MavenElisionService.ApplyPlan plan,
      ArtifactCoordinate coordinate,
      Path dependency,
      Path productionSources,
      Path testSources,
      Path productionOutput,
      Path testOutput,
      Path productionResources,
      Path testResources) {}
}
