/* WHY: Proves rooted provider bytecode and metadata survive trimming. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.jar.JarFile;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Checks physical trimming for a classpath resource-root descriptor. */
@SuppressWarnings("PMD.AvoidDuplicateLiterals")
/* package */ final class NativeImageConfigurationResourceRootTrimTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Creates the isolated physical-trim fixture. */
  /* package */ NativeImageConfigurationResourceRootTrimTest() {
    super();
  }

  /* package */
  @Test
  void keepsDescriptorAndItsClassWhileTrimmingUnrelatedProviderBytecode()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        NativeImageExternalConfigurationInputTestSupport.appendEntries(
            temporaryDirectory,
            fixture.snapshot("a").filePath(),
            "a-with-configuration-resource-root.jar",
            Map.of(
                "META-INF/native-image/test/native-image.properties",
                "Args = -H:ConfigurationResourceRoots=config-root/test\n"));
    final Path provider =
        NativeImageExternalConfigurationInputTestSupport.appendEntries(
            temporaryDirectory,
            fixture.snapshot("b").filePath(),
            "b-with-configuration-resource-root-descriptor.jar",
            Map.of(
                "config-root/test/reflect-config.json",
                "[{\"name\":\"closure.b.Middle\"},{\"name\":\"closure.c.Leaf\"}]"),
            Map.of(
                "closure/b/Middle.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Middle.class")),
                "closure/b/Unused.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Unused.class"))));
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "a", declaring);
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "b", provider);
    final Path trace = temporaryDirectory.resolve("configuration-root-trace.lst");
    Files.writeString(trace, "closure.a.Entry\n");
    final Path sourceRoot =
        Files.createDirectories(temporaryDirectory.resolve("root-trim-sources/app"));
    Files.writeString(
        sourceRoot.resolve("Application.java"), "package app; public class Application {}\n");
    fixture.mavenProject().getBuild().setSourceDirectory(sourceRoot.getParent().toString());
    fixture.mavenProject().addCompileSourceRoot(sourceRoot.getParent().toString());
    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            new ElisionAnalysisModel.AnalysisOptions(
                List.of(trace.toFile()),
                List.of(),
                null,
                null,
                new ElisionAnalysisModel.CompletenessOptions(false, false, false, true),
                new ElisionAnalysisModel.TrimOptions(
                    true,
                    List.of(),
                    false,
                    List.of(),
                    false,
                    MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                    MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
                new ElisionAnalysisModel.DynamicRootOptions(true)));
    final ElisionAnalysisModel.Analysis analysis = service.finish(prepared);
    final ArtifactTrimRecord providerTrim =
        analysis.trimResult().records().stream()
            .filter(record -> record.coordinate().equals(fixture.coordinate("b")))
            .findFirst()
            .orElseThrow();
    final boolean descriptorPreserved;
    final boolean rootedClassPreserved;
    final boolean unrelatedClassRemoved;
    try (JarFile output = new JarFile(providerTrim.trimmedPath().toFile())) {
      descriptorPreserved = output.getEntry("config-root/test/reflect-config.json") != null;
      rootedClassPreserved = output.getEntry("closure/b/Middle.class") != null;
      unrelatedClassRemoved = output.getEntry("closure/b/Unused.class") == null;
    }

    assertThat(
            List.of(
                prepared.dynamicRootInputs().resourceProviderArtifacts(),
                prepared.dynamicRootInputs().classNames(),
                prepared.rawDecision().retainedArtifacts(),
                List.of(
                    analysis.trimResult().configuredPassThroughArtifacts(),
                    analysis.trimResult().multiReleasePassthroughArtifacts(),
                    analysis.trimResult().moduleInfoPassthroughArtifacts()),
                providerTrim.totalClasses(),
                providerTrim.retainedClasses(),
                descriptorPreserved,
                rootedClassPreserved,
                unrelatedClassRemoved))
        .containsExactly(
            java.util.Set.of(fixture.coordinate("b")),
            java.util.Set.of("closure.b.Middle", "closure.c.Leaf"),
            java.util.Set.of(
                fixture.coordinate("a"), fixture.coordinate("b"), fixture.coordinate("c")),
            List.of(List.of(), List.of(), List.of()),
            2,
            1,
            true,
            true,
            true);
  }

  /* package */
  @Test
  void retainsClassAndProviderThroughElideWhenCombinedDirectAndPointerDuplicatesCoexist()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path standaloneA = temporaryDirectory.resolve("a-standalone-combined-dup.jar");
    io.github.spockz.elider.test.CompilationFixtureSupport.compileToJar(
        standaloneA,
        temporaryDirectory.resolve("a-standalone-src"),
        Map.of("Entry.java", "package closure.a; public class Entry {}"),
        null,
        21);

    final String resourceEntry = "META-INF/native-image/test/resource-config.json";
    final String includeMiddle =
        "{\"resources\":{\"includes\":[{\"pattern\":\"closure/b/Middle[.]class\"}]}}";
    final String excludeMiddle =
        "{\"resources\":{\"includes\":[{\"pattern\":\"closure/b/Other[.]class\"}],"
            + "\"excludes\":[{\"pattern\":\"closure/b/Middle[.]class\"}]}}";
    final Path declaring = temporaryDirectory.resolve("a-combined-direct-and-pointer.jar");
    try (JarFile baseA = new JarFile(standaloneA.toFile());
        java.util.jar.JarOutputStream out =
            new java.util.jar.JarOutputStream(Files.newOutputStream(declaring))) {
      copyEntries(baseA, out);
      putUtf8(
          out,
          "META-INF/native-image/test/native-image.properties",
          "Args = -H:ResourceConfigurationResources=" + resourceEntry + "\n");
      putUtf8(out, "META-INF/native-image/test/resource-confi1.json", excludeMiddle);
      putUtf8(out, "META-INF/native-image/test/resource-confi2.json", includeMiddle);
      putUtf8(out, "META-INF/native-image/test/resource-confi3.json", excludeMiddle);
    }
    String raw =
        new String(Files.readAllBytes(declaring), java.nio.charset.StandardCharsets.ISO_8859_1);
    raw =
        raw.replace("resource-confi1.json", "resource-config.json")
            .replace("resource-confi2.json", "resource-config.json")
            .replace("resource-confi3.json", "resource-config.json");
    Files.write(declaring, raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));

    final Path provider =
        NativeImageExternalConfigurationInputTestSupport.appendEntries(
            temporaryDirectory,
            fixture.snapshot("b").filePath(),
            "b-combined-dup-provider.jar",
            Map.of(),
            Map.of(
                "closure/b/Middle.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Middle.class")),
                "closure/b/Unused.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Unused.class"))));
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "a", declaring);
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "b", provider);

    final Path trace = temporaryDirectory.resolve("combined-dup-trace.lst");
    Files.writeString(trace, "closure.a.Entry\n");
    final Path sourceRoot =
        Files.createDirectories(temporaryDirectory.resolve("combined-dup-sources/app"));
    Files.writeString(
        sourceRoot.resolve("Application.java"), "package app; public class Application {}\n");
    fixture.mavenProject().getBuild().setSourceDirectory(sourceRoot.getParent().toString());
    fixture.mavenProject().addCompileSourceRoot(sourceRoot.getParent().toString());

    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            new ElisionAnalysisModel.AnalysisOptions(
                List.of(trace.toFile()),
                List.of(),
                null,
                null,
                new ElisionAnalysisModel.CompletenessOptions(false, false, false, true),
                new ElisionAnalysisModel.TrimOptions(
                    true,
                    List.of(),
                    false,
                    List.of(),
                    false,
                    MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                    MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
                new ElisionAnalysisModel.DynamicRootOptions(true)));
    final ElisionAnalysisModel.Analysis analysis = service.finish(prepared);
    final ArtifactTrimRecord providerTrim =
        analysis.trimResult().records().stream()
            .filter(record -> record.coordinate().equals(fixture.coordinate("b")))
            .findFirst()
            .orElseThrow();
    final boolean middlePreserved;
    final boolean unusedRemoved;
    try (JarFile output = new JarFile(providerTrim.trimmedPath().toFile())) {
      middlePreserved = output.getEntry("closure/b/Middle.class") != null;
      unusedRemoved = output.getEntry("closure/b/Unused.class") == null;
    }

    org.junit.jupiter.api.Assertions.assertAll(
        "Published archive retains metadata-rooted class and drops unrelated classes",
        () -> assertThat(prepared.dynamicRootInputs().classNames()).contains("closure.b.Middle"),
        () ->
            assertThat(prepared.rawDecision().retainedArtifacts())
                .contains(fixture.coordinate("b")),
        () ->
            org.junit.jupiter.api.Assertions.assertTrue(
                middlePreserved, "metadata-rooted class should survive in published output"),
        () ->
            org.junit.jupiter.api.Assertions.assertTrue(
                unusedRemoved, "unrelated provider class should be trimmed"));
  }

  private static void copyEntries(final JarFile source, final java.util.jar.JarOutputStream out)
      throws IOException {
    for (final java.util.jar.JarEntry entry : source.stream().toList()) {
      if (!entry.isDirectory()) {
        copyEntry(source, out, entry);
      }
    }
  }

  private static void copyEntry(
      final JarFile source,
      final java.util.jar.JarOutputStream out,
      final java.util.jar.JarEntry entry)
      throws IOException {
    out.putNextEntry(new java.util.jar.JarEntry(entry.getName()));
    try (java.io.InputStream input = source.getInputStream(entry)) {
      input.transferTo(out);
    }
    out.closeEntry();
  }

  private static void putUtf8(
      final java.util.jar.JarOutputStream out, final String name, final String content)
      throws IOException {
    out.putNextEntry(new java.util.jar.JarEntry(name));
    out.write(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    out.closeEntry();
  }
}
