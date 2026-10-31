/* WHY: Proves rooted provider bytecode and metadata survive trimming. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Checks physical trimming for a classpath resource-root descriptor. */
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
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-configuration-resource-root.jar",
            Map.of(
                "META-INF/native-image/test/native-image.properties",
                "Args = -H:ConfigurationResourceRoots=config-root/test\n"));
    final Path provider =
        appendEntries(
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
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", provider);
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
                new ElisionAnalysisModel.CompletenessOptions(true, false, false, true),
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

  private Path appendEntries(
      final Path source, final String destinationName, final Map<String, String> additions)
      throws IOException {
    return appendEntries(source, destinationName, additions, Map.of());
  }

  private Path appendEntries(
      final Path source,
      final String destinationName,
      final Map<String, String> additions,
      final Map<String, byte[]> classAdditions)
      throws IOException {
    final Path destination = temporaryDirectory.resolve(destinationName);
    try (JarFile archive = new JarFile(source.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(destination))) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        copyEntry(archive, output, entries.nextElement());
      }
      for (final Map.Entry<String, String> addition : additions.entrySet()) {
        writeEntry(output, addition.getKey(), addition.getValue().getBytes(StandardCharsets.UTF_8));
      }
      for (final Map.Entry<String, byte[]> addition : classAdditions.entrySet()) {
        writeEntry(output, addition.getKey(), addition.getValue());
      }
    }
    return destination;
  }

  private static void copyEntry(
      final JarFile archive, final JarOutputStream output, final JarEntry entry)
      throws IOException {
    output.putNextEntry(new JarEntry(entry.getName()));
    try (InputStream input = archive.getInputStream(entry)) {
      input.transferTo(output);
    }
    output.closeEntry();
  }

  private static void writeEntry(
      final JarOutputStream output, final String name, final byte[] content) throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(content);
    output.closeEntry();
  }

  private static void replaceArtifactFile(
      final Fixture fixture, final String artifactId, final Path replacement) {
    fixture.artifacts().stream()
        .filter(artifact -> artifactId.equals(artifact.getArtifactId()))
        .findFirst()
        .orElseThrow()
        .setFile(replacement.toFile());
  }
}
