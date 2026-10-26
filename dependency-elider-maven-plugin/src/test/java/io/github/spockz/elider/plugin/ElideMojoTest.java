// WHY: Verifies goal skipping and real artifact-view mutation through the Maven goal.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.JdkApiClassPoolReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.tools.ToolProvider;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies goal skipping and trace-based artifact-view mutation. */
// This fixture covers Maven, archive, bytecode, and SBOM integration APIs.
@SuppressWarnings({
  "PMD.ExcessiveImports",
  "PMD.AvoidAccessibilityAlteration",
  "PMD.AvoidDuplicateLiterals",
  "PMD.TooManyMethods",
  "PMD.CouplingBetweenObjects",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.LawOfDemeter",
  "PMD.ShortVariable",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
final class ElideMojoTest {
  /** Root module descriptor entry used by projected fixture archives. */
  private static final String MODULE_INFO_CLASS = "module-info.class";

  /** Temporary directory for synthetic JARs and runtime traces. */
  @TempDir private Path tempDir;

  /** Creates the focused test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  ElideMojoTest() {}

  @Test
  void skipReturnsWithoutAccessingProjectState() throws ReflectiveOperationException {
    final ElideMojo mojo = new ElideMojo();
    final Field skip = ElideMojo.class.getDeclaredField("skip");
    skip.setAccessible(true);
    skip.setBoolean(mojo, true);

    assertThatCode(mojo::execute).doesNotThrowAnyException();
  }

  @Test
  void retainsCompileVisibleArtifactsInResolvedAndDirectViews()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        runtimeArtifact(
            "used",
            compileJarSources(
                "used",
                java.util.Map.of("Sample.java", "package used; public class Sample {}"),
                null));
    final Artifact unused = artifact("unused", "unused/Idle.class");
    final Set<Artifact> resolved = new LinkedHashSet<>(List.of(used, unused));
    final Set<Artifact> direct = new LinkedHashSet<>(List.of(used, unused));
    final MavenProject project = new MavenProject();
    project.setArtifacts(resolved);
    project.setDependencyArtifacts(direct);
    execute(project, "used/Sample\n");

    assertThat(project.getArtifacts()).isNotSameAs(resolved);
    assertThat(project.getArtifacts()).containsExactlyInAnyOrder(used, unused);
    assertThat(project.getDependencyArtifacts()).isSameAs(direct);
    assertThat(project.getDependencyArtifacts()).containsExactlyInAnyOrder(used, unused);
    final Artifact addedLater = artifact("later", "later/Added.class");
    project.getArtifacts().add(addedLater);
    project.getDependencyArtifacts().add(addedLater);
    assertThat(project.getArtifacts()).contains(addedLater);
    assertThat(project.getDependencyArtifacts()).contains(addedLater);
  }

  @Test
  @SuppressWarnings("PMD.NcssCount")
  void trimJarsRedirectsTheArtifactAndWritesPedigreeSbom()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact runtime = compiledArtifact();
    final Artifact directRuntime =
        runtimeArtifact("runtime-dependency", runtime.getFile().toPath());
    final Artifact unusedRuntime = artifact("unused-runtime", "unused/Entry.class");
    unusedRuntime.setScope("runtime");
    final MavenProject project =
        project(runtime, new LinkedHashSet<>(List.of(directRuntime)), unusedRuntime);
    final Set<Artifact> directBefore = project.getDependencyArtifacts();
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setName("Consumer");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("build").toString());
    project.setBuild(build);
    final Path original = runtime.getFile().toPath();
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("sample.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("trim-report.json").toFile());
    set(mojo, "trimJars", true);
    set(mojo, "sbomFile", tempDir.resolve("build/dependency-elider-sbom.cdx.json").toFile());

    mojo.execute();

    assertThat(runtime.getFile().toPath()).isNotEqualTo(original).isRegularFile();
    assertThat(directRuntime.getFile().toPath()).isEqualTo(runtime.getFile().toPath());
    assertThat(project.getArtifacts()).contains(runtime);
    assertThat(project.getArtifacts()).doesNotContain(unusedRuntime);
    assertThat(project.getDependencyArtifacts()).isSameAs(directBefore).contains(directRuntime);
    try (JarFile trimmed = new JarFile(runtime.getFile())) {
      assertThat(trimmed.getEntry("sample/Keep.class")).isNotNull();
      assertThat(trimmed.getEntry("sample/Helper.class")).isNotNull();
      assertThat(trimmed.getEntry("sample/Drop.class")).isNull();
    }
    assertThat(tempDir.resolve("build/dependency-elider-sbom.cdx.json")).isRegularFile();
    assertThat(original).isRegularFile();

    runtime.setFile(original.toFile());
    directRuntime.setFile(original.toFile());
    final MavenElisionService.Analysis cachedAnalysis =
        new MavenElisionService()
            .analyze(
                project,
                List.of(writeTrace("sample.Keep\n").toFile()),
                List.of(),
                null,
                null,
                false,
                true,
                List.of());
    assertThat(cachedAnalysis.trimAnalysisRuns()).isZero();
    assertThat(cachedAnalysis.trimCacheHits()).isPositive();
    final Path expectedTrimmedPath =
        tempDir.resolve("build/elided-artifacts/org.example-runtime-dependency-1.0-trimmed.jar");
    assertThat(cachedAnalysis.trimRecords())
        .singleElement()
        .satisfies(record -> assertThat(record.trimmedPath()).isEqualTo(expectedTrimmedPath));
    final Path cacheManifest = tempDir.resolve("build/elided-artifacts/.trim-analysis-cache.json");
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode manifest = (ObjectNode) mapper.readTree(cacheManifest.toFile());
    ((ObjectNode) manifest.path("entries").get(0)).putNull("trimmedSha256");
    mapper.writeValue(cacheManifest.toFile(), manifest);
    final String fingerprint = manifest.path("fingerprint").asText();
    final MavenElisionService.Analysis malformedCacheAnalysis = analyzeTrim(project);
    assertThat(malformedCacheAnalysis.trimAnalysisRuns()).isPositive();

    for (final String field : List.of("roots", "retainedClassNames", "reachableLibraryClasses")) {
      final ObjectNode withNullMember = (ObjectNode) mapper.readTree(cacheManifest.toFile());
      final ObjectNode entry = (ObjectNode) withNullMember.path("entries").get(0);
      final com.fasterxml.jackson.databind.node.ArrayNode values =
          (com.fasterxml.jackson.databind.node.ArrayNode) entry.path(field);
      if (values.isEmpty()) {
        values.addNull();
      } else {
        values.set(0, com.fasterxml.jackson.databind.node.NullNode.getInstance());
      }
      mapper.writeValue(cacheManifest.toFile(), withNullMember);
      assertThat(analyzeTrim(project).trimAnalysisRuns()).isPositive();
    }

    Files.writeString(cacheManifest, "null");
    assertThat(analyzeTrim(project).trimAnalysisRuns()).isPositive();

    final ObjectNode nullEntries = mapper.createObjectNode();
    nullEntries.put("fingerprint", fingerprint);
    nullEntries.putNull("entries");
    mapper.writeValue(cacheManifest.toFile(), nullEntries);
    assertThat(analyzeTrim(project).trimAnalysisRuns()).isPositive();

    final ObjectNode nullEntry = mapper.createObjectNode();
    nullEntry.put("fingerprint", fingerprint);
    nullEntry.putArray("entries").addNull();
    mapper.writeValue(cacheManifest.toFile(), nullEntry);
    assertThat(analyzeTrim(project).trimAnalysisRuns()).isPositive();

    Files.writeString(expectedTrimmedPath, "tampered output");
    final MavenElisionService.Analysis repairedAnalysis = analyzeTrim(project);
    assertThat(repairedAnalysis.trimAnalysisRuns()).isPositive();
    assertThat(expectedTrimmedPath).isRegularFile();
    mojo.execute();
    assertThat(runtime.getFile().toPath()).isEqualTo(expectedTrimmedPath);

    runtime.setFile(original.toFile());
    directRuntime.setFile(original.toFile());
    Files.delete(expectedTrimmedPath);
    final MavenElisionService.Analysis missingOutputAnalysis = analyzeTrim(project);
    assertThat(missingOutputAnalysis.trimAnalysisRuns()).isPositive();
    assertThat(expectedTrimmedPath).isRegularFile();
  }

  @Test
  void multiReleaseTargetsPassThroughAndSeedReverseClassClosure()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final MultiReleaseFixture fixture = multiReleaseFixture("mr-default");
    final byte[] originalMultiReleaseBytes = Files.readAllBytes(fixture.multiReleasePath());
    final Path projectionDirectory = tempDir.resolve("mr-projections");
    final Path javaNineProjection =
        MultiReleaseLibraryProjection.create(
            fixture.multiReleasePath(),
            new ArtifactCoordinate("org.example", "mr-default-root", "1.0", "jar", "", "runtime"),
            projectionDirectory,
            9);
    final Path javaTwentyOneProjection =
        MultiReleaseLibraryProjection.create(
            fixture.multiReleasePath(),
            new ArtifactCoordinate("org.example", "mr-default-root", "1.0", "jar", "", "runtime"),
            projectionDirectory,
            21);
    final DependencyJarTrimmer trimmer = new DependencyJarTrimmer();
    final DependencyJarTrimmer.TrimAnalysis javaNineAnalysis =
        trimmer.analyzeUnchangedPassThrough(
            javaNineProjection,
            List.of(fixture.candidatePath()),
            new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 9),
            archiveClassNames(javaNineProjection));
    final DependencyJarTrimmer.TrimAnalysis javaTwentyOneAnalysis =
        trimmer.analyzeUnchangedPassThrough(
            javaTwentyOneProjection,
            List.of(fixture.candidatePath()),
            new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 21),
            archiveClassNames(javaTwentyOneProjection));
    assertThat(javaNineAnalysis.reachableLibraryClasses()).doesNotContain("candidate/Helper");
    assertThat(javaTwentyOneAnalysis.reachableLibraryClasses()).contains("candidate/Helper");
    final List<String> warnings = new ArrayList<>();
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(recordingLog(warnings));
    set(mojo, "project", fixture.project());
    set(mojo, "traceFiles", List.of(writeTrace("mrroot.Root\ncandidate.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("mr-default-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("mr-default-build/sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(fixture.multiRelease().getFile().toPath()).isEqualTo(fixture.multiReleasePath());
    assertThat(Files.readAllBytes(fixture.multiReleasePath())).isEqualTo(originalMultiReleaseBytes);
    assertThat(fixture.candidate().getFile().toPath()).isNotEqualTo(fixture.candidatePath());
    assertThat(warnings)
        .anySatisfy(
            warning ->
                assertThat(warning)
                    .contains("multi-release dependency unchanged")
                    .contains("unchanged external links are tolerated")
                    .contains("org.example:mr-default-root:jar:1.0"));
    try (JarFile trimmed = new JarFile(fixture.candidate().getFile())) {
      assertThat(trimmed.getEntry("candidate/Keep.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Helper.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Drop.class")).isNull();
    }
    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {
              fixture.multiReleasePath().toUri().toURL(),
              fixture.candidate().getFile().toURI().toURL()
            })) {
      loader.loadClass("mrroot.Root").getMethod("execute").invoke(null);
    } catch (final java.lang.reflect.InvocationTargetException exception) {
      throw new AssertionError(
          "The effective Java 21 MR method could not call candidate.Helper", exception);
    } catch (final ReflectiveOperationException exception) {
      throw new AssertionError("The effective Java 21 MR method could not be invoked", exception);
    }
  }

  @Test
  void configuredPassThroughToleratesItsMissingOptionalReferenceAndKeepsLinkedCandidate()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path candidateWithBridgeStub =
        compileJarSources(
            "configured-pass-through-candidate-with-bridge-stub",
            java.util.Map.of(
                "Keep.java",
                "package caller; public class Keep { public static void execute() { "
                    + "bridge.Root.execute(); } }",
                "Drop.java",
                "package caller; public class Drop {}",
                "Root.java",
                "package bridge; public class Root { public static void execute() {} }"),
            null);
    final Path candidatePath =
        writeJarWithoutClass(
            "configured-pass-through-candidate.jar", candidateWithBridgeStub, "bridge/Root.class");
    final Path helperPath =
        compileJarSources(
            "configured-pass-through-helper",
            java.util.Map.of(
                "Helper.java", "package candidate; public class Helper { public void touch() {} }",
                "Entry.java", "package candidate; public class Entry {}",
                "Drop.java", "package candidate; public class Drop {}"),
            null);
    final Path rootWithOptionalStub =
        compileJarSources(
            "configured-pass-through-root",
            java.util.Map.of(
                "Root.java",
                "package bridge; public class Root { public static void execute() { "
                    + "new candidate.Helper().touch(); } "
                    + "public void optional() { "
                    + "new org.example.optional.ScriptEvaluator().run(); } }",
                "ScriptEvaluator.java",
                "package org.example.optional; public class ScriptEvaluator { "
                    + "public void run() {} }"),
            helperPath);
    final Path rootPath =
        writeJarWithoutClass(
            "configured-pass-through.jar",
            rootWithOptionalStub,
            "org/example/optional/ScriptEvaluator.class");
    final Path candidateWithOptionalStub =
        compileJarSources(
            "strict-candidate",
            java.util.Map.of(
                "Keep.java",
                "package strictcandidate; public class Keep { public static void call() { "
                    + "new org.example.optional.ScriptEvaluator().run(); } }",
                "ScriptEvaluator.java",
                "package org.example.optional; public class ScriptEvaluator { "
                    + "public void run() {} }"),
            null);
    final Path candidateWithoutOptional =
        writeJarWithoutClass(
            "strict-candidate-without-optional.jar",
            candidateWithOptionalStub,
            "org/example/optional/ScriptEvaluator.class");
    final Artifact passThrough = runtimeArtifact("explicit-pass-through", rootPath);
    final Artifact candidate = runtimeArtifact("configured-pass-through-candidate", candidatePath);
    final Artifact helper = runtimeArtifact("configured-pass-through-helper", helperPath);
    final Artifact strictCandidate = runtimeArtifact("strict-candidate", candidateWithoutOptional);
    final Set<Artifact> passThroughArtifacts =
        new LinkedHashSet<>(List.of(passThrough, candidate, helper));
    final MavenProject passThroughProject =
        projectForArtifacts("configured-pass-through", passThroughArtifacts);
    final List<String> warnings = new ArrayList<>();
    final ElideMojo passThroughMojo = new ElideMojo();
    passThroughMojo.setLog(recordingLog(warnings));
    set(passThroughMojo, "project", passThroughProject);
    set(
        passThroughMojo,
        "traceFiles",
        List.of(writeTrace("caller.Keep\ncandidate.Entry\n").toFile()));
    set(
        passThroughMojo,
        "reportFile",
        tempDir.resolve("configured-pass-through-report.json").toFile());
    set(
        passThroughMojo,
        "sbomFile",
        tempDir.resolve("configured-pass-through-build/sbom.json").toFile());
    set(passThroughMojo, "trimJars", true);
    set(
        passThroughMojo,
        "excludedArtifacts",
        List.of("org.example:configured-pass-through-helper"));
    set(
        passThroughMojo,
        "trimSkipArtifacts",
        List.of("org.example:explicit-pass-through:1.0:jar:"));
    final byte[] originalPassThroughBytes = Files.readAllBytes(rootPath);

    passThroughMojo.execute();

    assertThat(passThrough.getFile().toPath()).isEqualTo(rootPath);
    assertThat(Files.readAllBytes(rootPath)).isEqualTo(originalPassThroughBytes);
    assertThat(warnings)
        .anySatisfy(
            warning ->
                assertThat(warning)
                    .contains("configured dependency unchanged")
                    .contains("external links from unchanged classes are tolerated")
                    .contains("org.example:explicit-pass-through:jar:1.0"));
    assertThat(passThroughProject.getArtifacts())
        .extracting(Artifact::getArtifactId)
        .contains("explicit-pass-through", "configured-pass-through-helper");
    assertThat(candidate.getFile().toPath()).isNotEqualTo(candidatePath);
    assertThat(helper.getFile().toPath()).isNotEqualTo(helperPath);
    try (JarFile trimmed = new JarFile(candidate.getFile())) {
      assertThat(trimmed.getEntry("caller/Keep.class")).isNotNull();
      assertThat(trimmed.getEntry("caller/Drop.class")).isNull();
    }
    try (JarFile trimmed = new JarFile(helper.getFile())) {
      assertThat(trimmed.getEntry("candidate/Helper.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Drop.class")).isNull();
    }
    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {
              candidate.getFile().toURI().toURL(),
              passThrough.getFile().toURI().toURL(),
              helper.getFile().toURI().toURL()
            })) {
      loader.loadClass("caller.Keep").getMethod("execute").invoke(null);
    } catch (final ReflectiveOperationException exception) {
      throw new AssertionError("The candidate to pass-through to helper chain failed", exception);
    }

    final Set<Artifact> strictArtifacts = new LinkedHashSet<>(List.of(strictCandidate));
    final MavenProject strictProject = projectForArtifacts("strict-candidate", strictArtifacts);
    final ElideMojo strictMojo = new ElideMojo();
    strictMojo.setLog(new SystemStreamLog());
    set(strictMojo, "project", strictProject);
    set(strictMojo, "traceFiles", List.of(writeTrace("strictcandidate.Keep\n").toFile()));
    set(strictMojo, "reportFile", tempDir.resolve("strict-candidate-report.json").toFile());
    set(strictMojo, "trimJars", true);
    assertThatThrownBy(strictMojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("unresolved references")
        .hasMessageContaining("org/example/optional/ScriptEvaluator");
    assertThat(strictCandidate.getFile().toPath()).isEqualTo(candidateWithoutOptional);
  }

  @Test
  void failHardRejectsMultiReleaseTrimTargetBeforeMutation()
      throws IOException, ReflectiveOperationException {
    final MultiReleaseFixture fixture = multiReleaseFixture("mr-fail-hard");
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", fixture.project());
    set(mojo, "traceFiles", List.of(writeTrace("mrroot.Root\ncandidate.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("mr-fail-hard-report.json").toFile());
    set(mojo, "trimJars", true);
    set(mojo, "failOnUnsupportedMultiRelease", true);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Unsupported multi-release implementation classes");
    assertThat(fixture.multiRelease().getFile().toPath()).isEqualTo(fixture.multiReleasePath());
    assertThat(fixture.candidate().getFile().toPath()).isEqualTo(fixture.candidatePath());
  }

  private MavenElisionService.Analysis analyzeTrim(final MavenProject project)
      throws IOException, MojoFailureException {
    return new MavenElisionService()
        .analyze(
            project,
            List.of(writeTrace("sample.Keep\n").toFile()),
            List.of(),
            null,
            null,
            false,
            true,
            List.of());
  }

  @Test
  void testScopeMultiReleaseJarIsLeftUntouchedDuringProductionTrimming()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact runtime = compiledArtifact();
    final Artifact directRuntime =
        runtimeArtifact("runtime-dependency", runtime.getFile().toPath());
    final Path versionedClassJar =
        compileJarSources(
            "test-scope-variant",
            java.util.Map.of(
                "testscope/Variant.java", "package testscope; public final class Variant {}"),
            null);
    final Path testJar = tempDir.resolve("test-scope-mr.jar");
    try (JarFile compiled = new JarFile(versionedClassJar.toFile());
        ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(testJar))) {
      output.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
      output.write(
          "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"
              .getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
      output.putNextEntry(new ZipEntry("META-INF/versions/11/testscope/Variant.class"));
      try (java.io.InputStream input =
          compiled.getInputStream(compiled.getEntry("testscope/Variant.class"))) {
        input.transferTo(output);
      }
      output.closeEntry();
    }
    final Artifact testOnly =
        new DefaultArtifact(
            "org.example",
            "test-only-mr",
            "1.0",
            "test",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    testOnly.setFile(testJar.toFile());
    final MavenProject project =
        project(runtime, new LinkedHashSet<>(List.of(directRuntime, testOnly)), testOnly);
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("scope-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("sample.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("scope-report.json").toFile());
    set(mojo, "trimJars", true);
    set(mojo, "sbomFile", tempDir.resolve("scope-build/sbom.json").toFile());

    mojo.execute();

    assertThat(runtime.getFile().toPath()).isNotEqualTo(tempDir.resolve("runtime-dependency.jar"));
    assertThat(testOnly.getFile().toPath()).isEqualTo(testJar);
    assertThat(project.getArtifacts()).contains(testOnly);
    assertThat(project.getDependencyArtifacts()).contains(testOnly);
    try (JarFile unchanged = new JarFile(testOnly.getFile())) {
      assertThat(unchanged.getEntry("META-INF/versions/11/testscope/Variant.class")).isNotNull();
    }
  }

  private Path compileDynamicRootJar() throws IOException {
    return compileJarSources(
        "End",
        java.util.Map.ofEntries(
            java.util.Map.entry(
                "End.java", "package chain; public interface End { static void touch() {} }"),
            java.util.Map.entry(
                "Provider.java", "package chain; public class Provider implements End {}"),
            java.util.Map.entry("Reflected.java", "package chain; public class Reflected {}"),
            java.util.Map.entry(
                "ProxyMarker.java", "package chain; public interface ProxyMarker {}"),
            java.util.Map.entry("SpringAuto.java", "package chain; public class SpringAuto {}"),
            java.util.Map.entry("Factory.java", "package chain; public class Factory {}"),
            java.util.Map.entry(
                "MetadataCondition.java", "package chain; public class MetadataCondition {}"),
            java.util.Map.entry(
                "NativeImageRoot.java", "package chain; public class NativeImageRoot {}"),
            java.util.Map.entry(
                "NativeImageJniRoot.java", "package chain; public class NativeImageJniRoot {}"),
            java.util.Map.entry(
                "NativeImageBundle.java", "package chain; public class NativeImageBundle {}"),
            java.util.Map.entry(
                "NativeImageBundleCondition.java",
                "package chain; public class NativeImageBundleCondition {}"),
            java.util.Map.entry(
                "NativeImageFeature.java", "package chain; public class NativeImageFeature {}"),
            java.util.Map.entry(
                "NativeImageBuildTime.java", "package chain; public class NativeImageBuildTime {}"),
            java.util.Map.entry(
                "AutoConfiguration.java",
                "package org.springframework.boot.autoconfigure; public class "
                    + "AutoConfiguration { public static class Nested {} }"),
            java.util.Map.entry(
                "ConditionalOnCheckpointRestore.java",
                "package org.springframework.boot.autoconfigure.condition; public class "
                    + "ConditionalOnCheckpointRestore {}"),
            java.util.Map.entry("Resource.java", "package org.crac; public interface Resource {}"),
            java.util.Map.entry(
                "KafkaStreamsAnnotationDrivenConfiguration.java",
                "package org.springframework.boot.autoconfigure.kafka; public class "
                    + "KafkaStreamsAnnotationDrivenConfiguration {}"),
            java.util.Map.entry(
                "TaskSchedulingConfigurations.java",
                "package org.springframework.boot.autoconfigure.task; public class "
                    + "TaskSchedulingConfigurations { public static class "
                    + "TaskSchedulerConfiguration {} }"),
            java.util.Map.entry("BeforeAuto.java", "package chain; public class BeforeAuto {}"),
            java.util.Map.entry("AfterAuto.java", "package chain; public class AfterAuto {}"),
            java.util.Map.entry("Unused.java", "package chain; public class Unused {}")),
        null);
  }

  @Test
  void trimRootsPropagateAcrossRetainedSiblingJars()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path cjar = compileDynamicRootJar();
    final Path bjar =
        compileJar(
            "Bridge",
            "package chain; public class Bridge { public void next() { new Helper().touch(); "
                + "End.touch(); } private static class Helper { void touch() {} } }",
            cjar);
    final Path compiledRoot =
        compileJar(
            "Root",
            "package chain; public class Root { public Bridge next() { return null; } }",
            bjar);
    final Path ajar =
        rewriteJar(
            compiledRoot,
            java.util.Map.of(
                "META-INF/native-image/test/reflect-config.json",
                "[{\"name\":\"chain.Reflected\"}]",
                "META-INF/native-image/test/proxy-config.json",
                "[[\"chain.ProxyMarker\"]]",
                "META-INF/native-image/test/tomcat-style/native-image.properties",
                "Args = -H:ReflectionConfigurationResources=${.}/tomcat-reflection.json "
                    + "-H:ResourceConfigurationResources=${.}/tomcat-resource.json\n",
                "META-INF/native-image/test/tomcat-style/tomcat-reflection.json",
                "[{\"name\":\"chain.NativeImageRoot\"}]",
                "META-INF/native-image/test/tomcat-style/tomcat-jni.json",
                "[{\"name\":\"chain.NativeImageJniRoot\"}]",
                "META-INF/native-image/test/tomcat-style/tomcat-resource.json",
                "{\"resources\":[{\"pattern\":\".*\"}],"
                    + "\"bundles\":[{\"name\":\"chain.NativeImageBundle\","
                    + "\"condition\":{\"typeReached\":\"chain.NativeImageBundleCondition\"}}]}",
                "META-INF/native-image/test/spring-web/native-image.properties",
                "Args = --enable-http --enable-https\n",
                "META-INF/native-image/test/spring-core/native-image.properties",
                "Args = --initialize-at-build-time=chain.NativeImageBuildTime \\\n"
                    + "  --features=chain.NativeImageFeature\n",
                "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports",
                "chain.SpringAuto\n",
                "META-INF/spring.factories",
                "org.example.Factory=chain.Factory\n"));
    final Path metadataJar =
        rewriteJar(
            cjar,
            java.util.Map.of(
                "META-INF/spring-autoconfigure-metadata.properties",
                "chain.SpringAuto.ConditionalOnClass=chain.MetadataCondition\n"
                    + "org.springframework.boot.autoconfigure.AutoConfiguration=\n"
                    + "org.springframework.boot.autoconfigure.AutoConfiguration$Nested=\n"
                    + "org.springframework.boot.autoconfigure.condition."
                    + "ConditionalOnCheckpointRestore."
                    + "ConditionalOnClass=org.crac.Resource\n"
                    + "org.springframework.boot.autoconfigure.kafka."
                    + "KafkaStreamsAnnotationDrivenConfiguration.ConditionalOnBean=\n"
                    + "org.springframework.boot.autoconfigure.kafka."
                    + "KafkaStreamsAnnotationDrivenConfiguration."
                    + "ConditionalOnWebApplication=SERVLET\n"
                    + "org.springframework.boot.autoconfigure.task.TaskSchedulingConfigurations$"
                    + "TaskSchedulerConfiguration.ConditionalOnBean=\n"
                    + "org.springframework.boot.autoconfigure.task.TaskSchedulingConfigurations$"
                    + "TaskSchedulerConfiguration.ConditionalOnWebApplication=\n"
                    + "org.springframework.boot.autoconfigure.condition."
                    + "ConditionalOnCheckpointRestore=\n"
                    + "chain.SpringAuto.AutoConfigureBefore=chain.BeforeAuto\n"
                    + "chain.SpringAuto.AutoConfigureAfter=chain.AfterAuto\n"
                    + "chain.SpringAuto.AutoConfigureOrder=10\n"));
    final Path serviceJar =
        descriptorJar("service-owner.jar", "META-INF/services/chain.End", "chain.Provider\n");
    final Artifact a = runtimeArtifact("chain-a", ajar);
    final Artifact b = runtimeArtifact("chain-b", bjar);
    final Artifact c = runtimeArtifact("chain-c", metadataJar);
    final Artifact serviceOwner = runtimeArtifact("service-owner", serviceJar);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(a, b, c, serviceOwner));
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId("chain-consumer");
    project.setVersion("1.0");
    project.setName("Chain Consumer");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("chain-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("chain.Root\n").toFile()));
    set(mojo, "excludedArtifacts", List.of("org.example:chain-b", "org.example:chain-c"));
    set(mojo, "reportFile", tempDir.resolve("chain-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("chain-build/chain-sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertClassMetadataRootsRetained(c);
    assertJarContains(a, "chain/Root.class");
    assertJarContains(b, "chain/Bridge.class");
    assertJarContains(b, "chain/Bridge$Helper.class");
    assertJarContains(c, "chain/End.class");
    assertJarContains(c, "chain/Provider.class");
    assertThat(serviceOwner.getFile().toPath()).isEqualTo(serviceJar);
    assertThat(project.getArtifacts()).contains(serviceOwner);
    try (JarFile trimmed = new JarFile(c.getFile())) {
      assertThat(trimmed.getEntry("chain/Unused.class")).isNull();
    }
  }

  private void assertClassMetadataRootsRetained(final Artifact artifact) throws IOException {
    assertJarContains(artifact, "chain/Reflected.class");
    assertJarContains(artifact, "chain/ProxyMarker.class");
    assertJarContains(artifact, "chain/SpringAuto.class");
    assertJarContains(artifact, "chain/Factory.class");
    assertJarContains(artifact, "chain/MetadataCondition.class");
    assertJarContains(artifact, "chain/NativeImageRoot.class");
    assertJarContains(artifact, "chain/NativeImageJniRoot.class");
    assertJarContains(artifact, "chain/NativeImageBundle.class");
    assertJarContains(artifact, "chain/NativeImageBundleCondition.class");
    assertJarContains(artifact, "chain/NativeImageBuildTime.class");
    assertJarContains(artifact, "chain/NativeImageFeature.class");
    assertJarContains(artifact, "org/springframework/boot/autoconfigure/AutoConfiguration.class");
    assertJarContains(
        artifact, "org/springframework/boot/autoconfigure/AutoConfiguration$Nested.class");
    assertJarContains(
        artifact,
        "org/springframework/boot/autoconfigure/condition/ConditionalOnCheckpointRestore.class");
    assertJarContains(
        artifact,
        "org/springframework/boot/autoconfigure/kafka/"
            + "KafkaStreamsAnnotationDrivenConfiguration.class");
    assertJarContains(
        artifact, "org/springframework/boot/autoconfigure/task/TaskSchedulingConfigurations.class");
    assertJarContains(
        artifact,
        "org/springframework/boot/autoconfigure/task/TaskSchedulingConfigurations$"
            + "TaskSchedulerConfiguration.class");
    assertJarContains(artifact, "org/crac/Resource.class");
    assertJarContains(artifact, "chain/BeforeAuto.class");
    assertJarContains(artifact, "chain/AfterAuto.class");
  }

  @Test
  void rootModuleInfoPassThroughRetainsAndExecutesHelperFromTrimmedSibling()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path candidateJar =
        compileJarSources(
            "module-pass-through-candidate",
            java.util.Map.of(
                "Entry.java",
                "package candidate; public class Entry {}",
                "Helper.java",
                "package candidate; public class Helper { public static String value() { "
                    + "return \"ok\"; } }",
                "Drop.java",
                "package candidate; public class Drop {}"),
            null);
    final Path compiledPassThrough =
        compileJarSources(
            "module-pass-through-root",
            java.util.Map.of(
                "Root.java",
                "package pass; public class Root { public static String call() { "
                    + "return candidate.Helper.value(); } }"),
            candidateJar);
    final Path passThroughJar =
        addRootModuleDescriptor(compiledPassThrough, "pass.through", "pass");
    final Artifact passThrough = runtimeArtifact("module-pass-through", passThroughJar);
    final Artifact candidate = runtimeArtifact("module-candidate", candidateJar);
    final MavenProject project =
        projectForArtifacts(
            "module-pass-through", new LinkedHashSet<>(List.of(passThrough, candidate)));
    final byte[] originalBytes = Files.readAllBytes(passThroughJar);
    final List<String> warnings = new ArrayList<>();
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(recordingLog(warnings));
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("candidate.Entry\npass.Root\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("module-pass-through-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("module-pass-through-build/sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(passThrough.getFile().toPath()).isEqualTo(passThroughJar);
    assertThat(Files.readAllBytes(passThroughJar)).isEqualTo(originalBytes);
    assertThat(project.getArtifacts()).contains(passThrough, candidate);
    assertThat(candidate.getFile().toPath()).isNotEqualTo(candidateJar);
    assertThat(warnings)
        .anySatisfy(
            warning ->
                assertThat(warning)
                    .contains("root-module-info dependency unchanged")
                    .contains("covers classpath closure, not module-path closure"));
    try (JarFile original = new JarFile(passThrough.getFile());
        JarFile trimmed = new JarFile(candidate.getFile())) {
      assertThat(original.getEntry("module-info.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Helper.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Drop.class")).isNull();
    }
    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {
              passThrough.getFile().toURI().toURL(), candidate.getFile().toURI().toURL()
            })) {
      assertThat(loader.loadClass("pass.Root").getMethod("call").invoke(null)).isEqualTo("ok");
    }
  }

  @Test
  void moduleInfoStrictModeFailsBeforePointerMutation()
      throws IOException, ReflectiveOperationException {
    final Path plainJar =
        compileJarSources(
            "module-info-strict",
            java.util.Map.of("Root.java", "package pass; public class Root {}"),
            null);
    final Path modularJar = addRootModuleDescriptor(plainJar, "strict.pass", "pass");
    final Artifact artifact = runtimeArtifact("module-info-strict", modularJar);
    final MavenProject project = projectForArtifacts("module-info-strict", Set.of(artifact));
    final byte[] originalBytes = Files.readAllBytes(modularJar);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("pass.Root\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("module-info-strict-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("module-info-strict-build/sbom.json").toFile());
    set(mojo, "trimJars", true);
    set(mojo, "failOnUnsupportedModuleInfo", true);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Unsupported root module descriptor");
    assertThat(artifact.getFile().toPath()).isEqualTo(modularJar);
    assertThat(project.getArtifacts()).containsExactly(artifact);
    assertThat(Files.readAllBytes(modularJar)).isEqualTo(originalBytes);
  }

  private Path addRootModuleDescriptor(
      final Path sourceJar, final String moduleName, final String exportedPackage)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V9, Opcodes.ACC_MODULE, "module-info", null, null, null);
    final ModuleVisitor module = writer.visitModule(moduleName, 0, null);
    module.visitRequire("java.base", 0, null);
    module.visitExport(exportedPackage.replace('.', '/'), 0);
    module.visitEnd();
    writer.visitEnd();
    final Path result = tempDir.resolve(sourceJar.getFileName() + "-modular.jar");
    try (JarFile input = new JarFile(sourceJar.toFile());
        ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(result))) {
      final java.util.Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (MODULE_INFO_CLASS.equals(entry.getName())) {
          continue;
        }
        output.putNextEntry(new ZipEntry(entry.getName()));
        try (java.io.InputStream content = input.getInputStream(entry)) {
          content.transferTo(output);
        }
        output.closeEntry();
      }
      output.putNextEntry(new ZipEntry(MODULE_INFO_CLASS));
      output.write(writer.toByteArray());
      output.closeEntry();
    }
    return result;
  }

  @Test
  void rootlessRetainedJarSeedsLinksIntoAnIndependentlyRootedSibling()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path callbackJar =
        compileJarSources(
            "callback",
            java.util.Map.of(
                "Callback.java",
                "package callback; public class Callback { public String invoke() { "
                    + "return \"callback\"; } }",
                "Independent.java",
                "package callback; public class Independent {}",
                "Unused.java",
                "package callback; public class Unused {}"),
            null);
    final Path helperJar =
        compileJarSources(
            "helper",
            java.util.Map.of(
                "Helper.java",
                "package callback; public class Helper { public static String call() { "
                    + "return new Callback().invoke(); } }"),
            callbackJar);
    final Artifact helper = runtimeArtifact("helper", helperJar);
    final Artifact callback = runtimeArtifact("callback", callbackJar);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(helper, callback));
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId("rootless-consumer");
    project.setVersion("1.0");
    project.setName("Rootless Consumer");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("rootless-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("callback.Independent\n").toFile()));
    set(mojo, "excludedArtifacts", List.of("org.example:helper"));
    set(mojo, "reportFile", tempDir.resolve("rootless-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("rootless-build/rootless-sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(helper.getFile().toPath()).isEqualTo(helperJar);
    assertJarContains(callback, "callback/Callback.class");
    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {helper.getFile().toURI().toURL(), callback.getFile().toURI().toURL()})) {
      assertThat(loader.loadClass("callback.Helper").getMethod("call").invoke(null))
          .isEqualTo("callback");
    }
    try (JarFile trimmed = new JarFile(callback.getFile())) {
      assertThat(trimmed.getEntry("callback/Unused.class")).isNull();
    }
  }

  @Test
  void malformedSpringMetadataFailsBeforeArtifactMutation()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("used", "used/Sample.class");
    final Path original = used.getFile().toPath();
    used.setFile(
        rewriteJar(
                original,
                java.util.Map.of(
                    "META-INF/spring-autoconfigure-metadata.properties", "not-a-supported-key=x\n"))
            .toFile());
    final Path malformed = used.getFile().toPath();
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("malformed-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Sample\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("malformed-report.json").toFile());
    set(mojo, "trimJars", true);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Unsupported Spring autoconfigure metadata key");
    assertThat(used.getFile().toPath()).isEqualTo(malformed).isNotEqualTo(original);
    assertThat(project.getArtifacts()).contains(used);
  }

  @Test
  void unsupportedNativeImageArgsFailBeforeArtifactMutation()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("native-image-unsupported", "used/Sample.class");
    final Path original = used.getFile().toPath();
    used.setFile(
        rewriteJar(
                original,
                java.util.Map.of(
                    "META-INF/native-image/test/native-image.properties",
                    "Args=-H:Class=example.NativeEntry\n"))
            .toFile());
    final Path input = used.getFile().toPath();
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    project.setGroupId("org.example");
    project.setArtifactId("native-image-consumer");
    project.setVersion("1.0");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("native-image-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Sample\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("native-image-report.json").toFile());
    set(mojo, "trimJars", true);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Unsupported native-image Args");
    assertThat(used.getFile().toPath()).isEqualTo(input).isNotEqualTo(original);
    assertThat(project.getArtifacts()).contains(used);
  }

  @Test
  void malformedNativeImageResourceBundlesFailBeforeArtifactMutation()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("native-image-malformed", "used/Sample.class");
    final Path original = used.getFile().toPath();
    used.setFile(
        rewriteJar(
                original,
                java.util.Map.of(
                    "META-INF/native-image/test/test-resource.json",
                    "{\"bundles\":\"not-an-array\"}"))
            .toFile());
    final Path input = used.getFile().toPath();
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    project.setGroupId("org.example");
    project.setArtifactId("native-image-consumer");
    project.setVersion("1.0");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("native-image-malformed-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Sample\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("native-image-malformed-report.json").toFile());
    set(mojo, "trimJars", true);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Malformed native-image bundles section");
    assertThat(used.getFile().toPath()).isEqualTo(input).isNotEqualTo(original);
    assertThat(project.getArtifacts()).contains(used);
  }

  @Test
  void trimCacheFingerprintTracksExactOrderedAnalysisInputs() throws IOException {
    final Path firstLibrary = tempDir.resolve("first.jar");
    final Path secondLibrary = tempDir.resolve("second.jar");
    final Path ctSym = tempDir.resolve("ct.sym");
    final Path otherJdkCtSym = tempDir.resolve("other-jdk/lib/ct.sym");
    final Path jmod = tempDir.resolve("java.base.jmod");
    Files.writeString(firstLibrary, "first-bytes");
    Files.writeString(secondLibrary, "second-bytes");
    Files.writeString(ctSym, "ct-sym-bytes");
    Files.createDirectories(otherJdkCtSym.getParent());
    Files.writeString(otherJdkCtSym, "other-jdk-platform-bytes");
    Files.writeString(jmod, "jmod-bytes");
    final java.nio.file.attribute.FileTime timestamp =
        java.nio.file.attribute.FileTime.fromMillis(1_700_000_000_000L);
    Files.setLastModifiedTime(firstLibrary, timestamp);
    Files.setLastModifiedTime(ctSym, timestamp);
    final List<String> candidateIdentities = List.of("org.example:first:1.0:jar");
    final String baseline =
        MavenDependencyTrimmer.fingerprintForInputs(
            candidateIdentities,
            List.of(firstLibrary, secondLibrary),
            Set.of("sample.Root"),
            List.of(ctSym),
            21,
            4,
            "proguard-core-9.1.10");

    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(secondLibrary, firstLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                21,
                4,
                "proguard-core-9.1.10"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                17,
                4,
                "proguard-core-9.1.10"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(otherJdkCtSym),
                21,
                4,
                "proguard-core-9.1.10"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.OtherRoot"),
                List.of(ctSym),
                21,
                4,
                "proguard-core-9.1.10"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(jmod),
                21,
                4,
                "proguard-core-9.1.10"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym, jmod),
                21,
                4,
                "proguard-core-9.1.10"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                21,
                5,
                "proguard-core-9.1.10"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                21,
                4,
                "proguard-core-9.1.11"))
        .isNotEqualTo(baseline);

    Files.writeString(firstLibrary, "other-bytes");
    Files.setLastModifiedTime(firstLibrary, timestamp);
    final String dependencyChangedFingerprint =
        MavenDependencyTrimmer.fingerprintForInputs(
            candidateIdentities,
            List.of(firstLibrary, secondLibrary),
            Set.of("sample.Root"),
            List.of(ctSym),
            21,
            4,
            "proguard-core-9.1.10");
    assertThat(dependencyChangedFingerprint).isNotEqualTo(baseline);
    final long ctSymSize = Files.size(ctSym);
    Files.writeString(ctSym, "xt-sym-bytes");
    Files.setLastModifiedTime(ctSym, timestamp);
    assertThat(Files.size(ctSym)).isEqualTo(ctSymSize);
    assertThat(Files.getLastModifiedTime(ctSym)).isEqualTo(timestamp);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                21,
                4,
                "proguard-core-9.1.10"))
        .isNotEqualTo(dependencyChangedFingerprint);
  }

  @Test
  void explicitTrimRootKeepsItsWholeArtifactOwnerAndTrimsOtherClasses()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        runtimeArtifact(
            "used",
            compileJarSources(
                "used",
                java.util.Map.of("Sample.java", "package used; public class Sample {}"),
                null));
    final Path explicitJar =
        compileJarSources(
            "explicit",
            java.util.Map.of(
                "Keep.java", "package explicit; public class Keep {}",
                "Drop.java", "package explicit; public class Drop {}"),
            null);
    final Artifact explicit = runtimeArtifact("explicit", explicitJar);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(used, explicit));
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId("explicit-consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("explicit-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Sample\n").toFile()));
    set(mojo, "trimRoots", List.of("explicit.Keep"));
    set(mojo, "reportFile", tempDir.resolve("explicit-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("explicit-build/explicit-sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(project.getArtifacts()).contains(explicit);
    assertJarContains(explicit, "explicit/Keep.class");
    try (JarFile trimmed = new JarFile(explicit.getFile())) {
      assertThat(trimmed.getEntry("explicit/Drop.class")).isNull();
    }
  }

  @Test
  void trimSbomIncludesRetainedPomArtifacts()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path dependencyJar =
        compileJarSources(
            "sbom-dependency",
            java.util.Map.of(
                "Keep.java", "package sbom; public class Keep {}",
                "Drop.java", "package sbom; public class Drop {}"),
            null);
    final Artifact jarArtifact = runtimeArtifact("sbom-dependency", dependencyJar);
    final Path pomFile = tempDir.resolve("descriptor-dependency.pom");
    Files.writeString(pomFile, "<project/>\n");
    final Artifact pomArtifact =
        new DefaultArtifact(
            "org.example",
            "descriptor-dependency",
            "1.0",
            "runtime",
            "pom",
            null,
            new DefaultArtifactHandler("pom"));
    pomArtifact.setFile(pomFile.toFile());
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(jarArtifact, pomArtifact));
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId("sbom-consumer");
    project.setVersion("1.0");
    project.setName("SBOM Consumer");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("pom-sbom-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("sbom.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("pom-sbom-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("pom-sbom-build/sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(project.getArtifacts()).contains(jarArtifact, pomArtifact);
    assertThat(tempDir.resolve("pom-sbom-build/sbom.json")).isRegularFile();
    assertJarContains(jarArtifact, "sbom/Keep.class");
    try (JarFile trimmed = new JarFile(jarArtifact.getFile())) {
      assertThat(trimmed.getEntry("sbom/Drop.class")).isNull();
    }
  }

  private Artifact compiledArtifact() throws IOException {
    final Path source = tempDir.resolve("trim-src/sample");
    final Path classes = tempDir.resolve("trim-classes");
    Files.createDirectories(source);
    Files.createDirectories(classes);
    Files.writeString(
        source.resolve("Keep.java"), "package sample; public class Keep { Helper helper; }");
    Files.writeString(source.resolve("Helper.java"), "package sample; public class Helper {}");
    Files.writeString(source.resolve("Drop.java"), "package sample; public class Drop {}");
    final int result =
        ToolProvider.getSystemJavaCompiler()
            .run(
                null,
                null,
                null,
                "--release",
                "21",
                "-d",
                classes.toString(),
                source.resolve("Keep.java").toString(),
                source.resolve("Helper.java").toString(),
                source.resolve("Drop.java").toString());
    if (result != 0) {
      throw new IOException("Could not compile the trimming lifecycle fixture");
    }
    final Path jar = tempDir.resolve("runtime-dependency.jar");
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
        java.util.stream.Stream<Path> paths = Files.walk(classes)) {
      for (final Path classFile : paths.filter(Files::isRegularFile).toList()) {
        output.putNextEntry(
            new ZipEntry(classes.relativize(classFile).toString().replace('\\', '/')));
        Files.copy(classFile, output);
        output.closeEntry();
      }
    }
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            "runtime-dependency",
            "1.0",
            "runtime",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(jar.toFile());
    return artifact;
  }

  private Path compileJar(final String className, final String source, final Path classpath)
      throws IOException {
    return compileJarSources(className, java.util.Map.of(className + ".java", source), classpath);
  }

  private Path compileJarSources(
      final String jarName, final java.util.Map<String, String> sources, final Path classpath)
      throws IOException {
    final Path sourceDirectory = tempDir.resolve(jarName + "-src");
    final Path output = tempDir.resolve(jarName + "-classes");
    Files.createDirectories(sourceDirectory);
    Files.createDirectories(output);
    final List<Path> sourceFiles = new ArrayList<>();
    for (final java.util.Map.Entry<String, String> source : sources.entrySet()) {
      final Path sourceFile = sourceDirectory.resolve(source.getKey());
      Files.createDirectories(sourceFile.getParent());
      Files.writeString(sourceFile, source.getValue());
      sourceFiles.add(sourceFile);
    }
    final List<String> arguments =
        new ArrayList<>(List.of("--release", "21", "-d", output.toString()));
    if (classpath != null) {
      arguments.addAll(List.of("-classpath", classpath.toString()));
    }
    sourceFiles.forEach(source -> arguments.add(source.toString()));
    final int result =
        ToolProvider.getSystemJavaCompiler()
            .run(null, null, null, arguments.toArray(String[]::new));
    if (result != 0) {
      throw new IOException("Could not compile cross-artifact trimming fixture " + jarName);
    }
    final Path jar = tempDir.resolve(jarName + ".jar");
    try (ZipOutputStream archive = new ZipOutputStream(Files.newOutputStream(jar));
        java.util.stream.Stream<Path> paths = Files.walk(output)) {
      for (final Path classFile : paths.filter(Files::isRegularFile).toList()) {
        archive.putNextEntry(
            new ZipEntry(output.relativize(classFile).toString().replace('\\', '/')));
        Files.copy(classFile, archive);
        archive.closeEntry();
      }
    }
    return jar;
  }

  private MultiReleaseFixture multiReleaseFixture(final String name) throws IOException {
    final Path candidatePath =
        compileJarSources(
            name + "-candidate",
            java.util.Map.of(
                "Keep.java", "package candidate; public class Keep {}",
                "Helper.java", "package candidate; public class Helper { public void touch() {} }",
                "Drop.java", "package candidate; public class Drop {}"),
            null);
    final Path rootClasses =
        compileJarSources(
            name + "-root-classes",
            java.util.Map.of(
                "Root.java",
                "package mrroot; public class Root { public static void execute() {} }"),
            candidatePath);
    final Path versionOnly =
        compileJarSources(
            name + "-version-only",
            java.util.Map.of(
                "Root.java",
                "package mrroot; public class Root { public static void execute() { "
                    + "new candidate.Helper().touch(); } public static void optional() { "
                    + "new org.example.optional.ScriptEvaluator().run(); } }",
                "ScriptEvaluator.java",
                "package org.example.optional; public class ScriptEvaluator { "
                    + "public void run() {} }"),
            candidatePath);
    final Path multiReleasePath =
        writeMultiReleaseJar(name + "-root.jar", rootClasses, versionOnly);
    final Artifact root = runtimeArtifact(name + "-root", multiReleasePath);
    final Artifact candidate = runtimeArtifact(name + "-candidate", candidatePath);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(root, candidate));
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId(name + "-consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve(name + "-build").toString());
    project.setBuild(build);
    return new MultiReleaseFixture(root, candidate, multiReleasePath, candidatePath, project);
  }

  private MavenProject projectForArtifacts(final String name, final Set<Artifact> artifacts) {
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId(name);
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve(name + "-build").toString());
    project.setBuild(build);
    return project;
  }

  private Path writeJarWithoutClass(
      final String outputName, final Path source, final String omittedClass) throws IOException {
    final Path outputJar = tempDir.resolve(outputName);
    try (JarFile input = new JarFile(source.toFile());
        java.util.jar.JarOutputStream output =
            new java.util.jar.JarOutputStream(Files.newOutputStream(outputJar))) {
      final java.util.Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (entry.isDirectory() || entry.getName().equals(omittedClass)) {
          continue;
        }
        output.putNextEntry(new JarEntry(entry.getName()));
        try (java.io.InputStream contents = input.getInputStream(entry)) {
          contents.transferTo(output);
        }
        output.closeEntry();
      }
    }
    return outputJar;
  }

  private Path writeMultiReleaseJar(final String name, final Path baseJar, final Path versionedJar)
      throws IOException {
    final Path result = tempDir.resolve(name);
    final java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarFile base = new JarFile(baseJar.toFile());
        JarFile versioned = new JarFile(versionedJar.toFile());
        java.util.jar.JarOutputStream output =
            new java.util.jar.JarOutputStream(Files.newOutputStream(result), manifest)) {
      copyJarEntries(base, output, "");
      copyJarEntries(versioned, output, "META-INF/versions/21/");
    }
    return result;
  }

  private static void copyJarEntries(
      final JarFile source, final java.util.jar.JarOutputStream output, final String prefix)
      throws IOException {
    final java.util.Enumeration<JarEntry> entries = source.entries();
    while (entries.hasMoreElements()) {
      final JarEntry entry = entries.nextElement();
      if (entry.isDirectory()
          || !entry.getName().endsWith(".class")
          || "org/example/optional/ScriptEvaluator.class".equals(entry.getName())) {
        continue;
      }
      output.putNextEntry(new JarEntry(prefix + entry.getName()));
      try (java.io.InputStream contents = source.getInputStream(entry)) {
        contents.transferTo(output);
      }
      output.closeEntry();
    }
  }

  // Log's defining loader must define the proxy interface used by the fixture.
  @SuppressWarnings("PMD.UseProperClassLoader")
  private static Log recordingLog(final List<String> warnings) {
    return (Log)
        java.lang.reflect.Proxy.newProxyInstance(
            Log.class.getClassLoader(),
            new Class<?>[] {Log.class},
            (proxy, method, arguments) -> {
              if ("warn".equals(method.getName())
                  && arguments != null
                  && arguments.length > 0
                  && arguments[0] instanceof CharSequence message) {
                warnings.add(message.toString());
              }
              return method.getReturnType() == boolean.class ? false : null;
            });
  }

  private record MultiReleaseFixture(
      Artifact multiRelease,
      Artifact candidate,
      Path multiReleasePath,
      Path candidatePath,
      MavenProject project) {}

  private static Set<String> archiveClassNames(final Path archivePath) throws IOException {
    final Set<String> names = new LinkedHashSet<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final java.util.Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final String name = entries.nextElement().getName();
        if (name.endsWith(".class")) {
          names.add(name.substring(0, name.length() - ".class".length()).replace('/', '.'));
        }
      }
    }
    return names;
  }

  private Path descriptorJar(final String name, final String entry, final String content)
      throws IOException {
    final Path jar = tempDir.resolve(name);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar))) {
      output.putNextEntry(new ZipEntry(entry));
      output.write(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
    }
    return jar;
  }

  private Path rewriteJar(final Path original, final java.util.Map<String, String> resources)
      throws IOException {
    final Path outputJar = tempDir.resolve("with-metadata-" + original.getFileName());
    try (JarFile inputJar = new JarFile(original.toFile());
        ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(outputJar))) {
      final java.util.Enumeration<JarEntry> entries = inputJar.entries();
      while (entries.hasMoreElements()) {
        final ZipEntry entry = entries.nextElement();
        output.putNextEntry(new ZipEntry(entry.getName()));
        try (java.io.InputStream stream = inputJar.getInputStream(entry)) {
          stream.transferTo(output);
        }
        output.closeEntry();
      }
      for (final java.util.Map.Entry<String, String> resource : resources.entrySet()) {
        output.putNextEntry(new ZipEntry(resource.getKey()));
        output.write(resource.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        output.closeEntry();
      }
    }
    return outputJar;
  }

  private Artifact runtimeArtifact(final String artifactId, final Path jar) {
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

  private void assertJarContains(final Artifact artifact, final String entry) throws IOException {
    assertThat(artifact.getFile().toPath())
        .isNotEqualTo(tempDir.resolve(artifact.getArtifactId() + ".jar"));
    try (JarFile jar = new JarFile(artifact.getFile())) {
      assertThat(jar.getEntry(entry)).isNotNull();
    }
  }

  private Path writeTrace(final String content) throws IOException {
    final Path trace = tempDir.resolve("trim-runtime.lst");
    Files.writeString(trace, content);
    return trace;
  }

  @Test
  void preservesAbsentAndPresentEmptyDirectViews()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used = artifact("used", "used/Sample.class");
    final MavenProject absent = project(used, null);
    final MavenProject presentEmpty = project(used, new LinkedHashSet<>());

    execute(absent, "used/Sample\n");
    execute(presentEmpty, "used/Sample\n");

    assertThat(absent.getDependencyArtifacts()).isNull();
    assertThat(presentEmpty.getDependencyArtifacts()).isEmpty();
  }

  @Test
  void invalidTraceFailsWithoutChangingEitherArtifactView()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("used", "used/Sample.class");
    final Artifact unused = artifact("unused", "unused/Idle.class");
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used, unused)), unused);
    final Set<Artifact> resolvedBefore = project.getArtifacts();
    final Set<Artifact> directBefore = project.getDependencyArtifacts();

    assertThatThrownBy(() -> execute(project, "missing/Sample\n"))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("no observed class matches any supplied dependency");
    assertThat(project.getArtifacts()).isSameAs(resolvedBefore).containsExactly(used, unused);
    assertThat(project.getDependencyArtifacts())
        .isSameAs(directBefore)
        .containsExactly(used, unused);
  }

  @Test
  void missingTraceFailsWithoutChangingEitherArtifactView()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("used", "used/Sample.class");
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    final Set<Artifact> resolvedBefore = project.getArtifacts();
    final Set<Artifact> directBefore = project.getDependencyArtifacts();
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("At least one supported trace input is required");
    assertThat(project.getArtifacts()).isSameAs(resolvedBefore).containsExactly(used);
    assertThat(project.getDependencyArtifacts()).isSameAs(directBefore).containsExactly(used);
  }

  private MavenProject project(final Artifact resolved, final Set<Artifact> direct) {
    return project(resolved, direct, null);
  }

  private MavenProject project(
      final Artifact resolved, final Set<Artifact> direct, final Artifact additionalResolved) {
    final MavenProject project = new MavenProject();
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(resolved));
    if (additionalResolved != null) {
      artifacts.add(additionalResolved);
    }
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(direct);
    return project;
  }

  private void execute(final MavenProject project, final String traceContent)
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path trace = tempDir.resolve("runtime.lst");
    Files.writeString(trace, traceContent);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "reportFile", tempDir.resolve("elide-report.json").toFile());
    mojo.execute();
  }

  private Artifact artifact(final String artifactId, final String classEntry) throws IOException {
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            "1.0",
            "compile",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(writeJar(artifactId + ".jar", classEntry).toFile());
    return artifact;
  }

  private Path writeJar(final String name, final String classEntry) throws IOException {
    final Path jar = tempDir.resolve(name);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar))) {
      output.putNextEntry(new ZipEntry(classEntry));
      output.write(new byte[] {0});
      output.closeEntry();
    }
    return jar;
  }

  private static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }
}
