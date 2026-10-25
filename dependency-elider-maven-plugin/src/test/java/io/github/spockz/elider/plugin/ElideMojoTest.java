// WHY: Verifies goal skipping and real artifact-view mutation through the Maven goal.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.lang.reflect.Field;
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
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies goal skipping and trace-based artifact-view mutation. */
@SuppressWarnings({
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
    assertThat(project.getDependencyArtifacts()).isNotSameAs(direct);
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
    final MavenProject project = project(runtime, new LinkedHashSet<>(List.of(directRuntime)));
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
    assertThat(project.getDependencyArtifacts()).contains(directRuntime);
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
  void trimRootsPropagateAcrossRetainedSiblingJars()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path cjar =
        compileJarSources(
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
                    "AutoConfiguration.java",
                    "package org.springframework.boot.autoconfigure; public class "
                        + "AutoConfiguration { public static class Nested {} }"),
                java.util.Map.entry(
                    "ConditionalOnCheckpointRestore.java",
                    "package org.springframework.boot.autoconfigure.condition; public class "
                        + "ConditionalOnCheckpointRestore {}"),
                java.util.Map.entry(
                    "Resource.java", "package org.crac; public interface Resource {}"),
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
                    + "org.springframework.boot.autoconfigure.task.TaskSchedulingConfigurations$"
                    + "TaskSchedulerConfiguration.ConditionalOnBean=\n"
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

    assertJarContains(a, "chain/Root.class");
    assertJarContains(b, "chain/Bridge.class");
    assertJarContains(b, "chain/Bridge$Helper.class");
    assertJarContains(c, "chain/End.class");
    assertJarContains(c, "chain/Provider.class");
    assertJarContains(c, "chain/Reflected.class");
    assertJarContains(c, "chain/ProxyMarker.class");
    assertJarContains(c, "chain/SpringAuto.class");
    assertJarContains(c, "chain/Factory.class");
    assertJarContains(c, "chain/MetadataCondition.class");
    assertJarContains(c, "org/springframework/boot/autoconfigure/AutoConfiguration.class");
    assertJarContains(c, "org/springframework/boot/autoconfigure/AutoConfiguration$Nested.class");
    assertJarContains(
        c, "org/springframework/boot/autoconfigure/condition/ConditionalOnCheckpointRestore.class");
    assertJarContains(
        c,
        "org/springframework/boot/autoconfigure/kafka/"
            + "KafkaStreamsAnnotationDrivenConfiguration.class");
    assertJarContains(
        c, "org/springframework/boot/autoconfigure/task/TaskSchedulingConfigurations.class");
    assertJarContains(
        c,
        "org/springframework/boot/autoconfigure/task/TaskSchedulingConfigurations$"
            + "TaskSchedulerConfiguration.class");
    assertJarContains(c, "org/crac/Resource.class");
    assertJarContains(c, "chain/BeforeAuto.class");
    assertJarContains(c, "chain/AfterAuto.class");
    assertThat(serviceOwner.getFile().toPath()).isEqualTo(serviceJar);
    assertThat(project.getArtifacts()).contains(serviceOwner);
    try (JarFile trimmed = new JarFile(c.getFile())) {
      assertThat(trimmed.getEntry("chain/Unused.class")).isNull();
    }
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
    try (java.net.URLClassLoader loader =
        new java.net.URLClassLoader(
            new java.net.URL[] {
              helper.getFile().toURI().toURL(), callback.getFile().toURI().toURL()
            })) {
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
  void trimCacheFingerprintTracksExactOrderedAnalysisInputs() throws IOException {
    final Path firstLibrary = tempDir.resolve("first.jar");
    final Path secondLibrary = tempDir.resolve("second.jar");
    final Path ctSym = tempDir.resolve("ct.sym");
    final Path jmod = tempDir.resolve("java.base.jmod");
    Files.writeString(firstLibrary, "first-bytes");
    Files.writeString(secondLibrary, "second-bytes");
    Files.writeString(ctSym, "ct-sym-bytes");
    Files.writeString(jmod, "jmod-bytes");
    final java.nio.file.attribute.FileTime timestamp =
        java.nio.file.attribute.FileTime.fromMillis(1_700_000_000_000L);
    Files.setLastModifiedTime(firstLibrary, timestamp);
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
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                21,
                4,
                "proguard-core-9.1.10"))
        .isNotEqualTo(baseline);
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
