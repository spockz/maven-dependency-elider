/* WHY: Proves IncludeResources keeps selected bytes during physical pruning. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
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

/** Verifies include-resource provider roots against actual trimmed JAR output. */
/* package */ final class NativeImageResourcePatternTrimTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Retains one provider resource and two logical class resources. */
  private final String includeArgument;

  /* package */ NativeImageResourcePatternTrimTest() {
    super();
    includeArgument =
        "-H:IncludeResources=assets/marker\\.txt|"
            + "closure/b/Middle\\.class|closure/c/Leaf\\.class";
  }

  /* package */
  @Test
  void matchingClassResourceKeepsItsClassAndMatchingProviderResources()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-include-resources.jar",
            Map.of(
                "META-INF/native-image/test/native-image.properties",
                "Args = " + includeArgument + "\n"),
            Map.of());
    final Path provider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-with-include-resources.jar",
            Map.of("assets/marker.txt", "included", "assets/other.txt", "unmatched"),
            Map.of(
                "closure/b/Middle.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Middle.class")),
                "closure/b/Unused.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Unused.class"))));
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", provider);
    final Path trace = temporaryDirectory.resolve("resource-pattern-trace.lst");
    Files.writeString(trace, "closure.a.Entry\n");

    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            MavenElisionServiceEffectiveAnalysisFixtures.options(
                List.of(trace.toFile()), null, true));
    final MavenElisionService.Analysis analysis = service.finish(prepared);
    final ArtifactTrimRecord providerTrim =
        analysis.trimRecords().stream()
            .filter(record -> record.coordinate().equals(fixture.coordinate("b")))
            .findFirst()
            .orElseThrow();
    final boolean rootedClassPresent;
    final boolean unrelatedClassAbsent;
    final boolean includedResourcePresent;
    final boolean unrelatedResourcePreserved;
    try (JarFile output = new JarFile(providerTrim.trimmedPath().toFile())) {
      rootedClassPresent = output.getEntry("closure/b/Middle.class") != null;
      unrelatedClassAbsent = output.getEntry("closure/b/Unused.class") == null;
      includedResourcePresent = output.getEntry("assets/marker.txt") != null;
      unrelatedResourcePreserved = output.getEntry("assets/other.txt") != null;
    }

    assertThat(
            List.of(
                prepared.dynamicRootInputs().classNames(),
                prepared.dynamicRootInputs().resourceProviderArtifacts(),
                providerTrim.totalClasses(),
                providerTrim.retainedClasses(),
                rootedClassPresent,
                unrelatedClassAbsent,
                includedResourcePresent,
                unrelatedResourcePreserved))
        .containsExactly(
            java.util.Set.of("closure.b.Middle", "closure.c.Leaf"),
            java.util.Set.of(fixture.coordinate("b"), fixture.coordinate("c")),
            2,
            1,
            true,
            true,
            true,
            true);
  }

  /* package */
  @Test
  void matchingOrdinaryResourceRetainsRuntimeArchiveWithUnreferencedClass() throws Exception {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-resource-only-include.jar",
            Map.of(
                "META-INF/native-image/test/native-image.properties",
                "Args = -H:IncludeResources=runtime/provider\\.dat\n"),
            Map.of());
    final Path provider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-resource-only-runtime.jar",
            Map.of("runtime/provider.dat", "provided"),
            Map.of(
                "closure/b/Unused.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Unused.class"))));
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", provider);
    final Path trace = temporaryDirectory.resolve("resource-only-trace.lst");
    Files.writeString(trace, "closure.a.Entry\n");

    final MavenElisionService.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                fixture.mavenProject(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));
    final boolean providerHasIndexedClass =
        prepared.index().classesByArtifact().entrySet().stream()
            .anyMatch(
                entry ->
                    entry.getKey().coordinate().equals(fixture.coordinate("b"))
                        && entry.getValue().contains("closure.b.Unused"));

    assertThat(
            List.of(
                prepared.dynamicRootInputs().classNames(),
                prepared.dynamicRootInputs().resourceProviderArtifacts(),
                prepared.rawDecision().retainedArtifacts(),
                providerHasIndexedClass))
        .containsExactly(
            java.util.Set.of(),
            java.util.Set.of(fixture.coordinate("b")),
            java.util.Set.of(fixture.coordinate("a"), fixture.coordinate("b")),
            true);
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
      for (final Map.Entry<String, String> entry : additions.entrySet()) {
        write(
            output,
            entry.getKey(),
            entry.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
      }
      for (final Map.Entry<String, byte[]> entry : classAdditions.entrySet()) {
        write(output, entry.getKey(), entry.getValue());
      }
    }
    return destination;
  }

  private static void copyEntry(
      final JarFile archive, final JarOutputStream output, final JarEntry entry)
      throws IOException {
    output.putNextEntry(new JarEntry(entry.getName()));
    try (java.io.InputStream input = archive.getInputStream(entry)) {
      input.transferTo(output);
    }
    output.closeEntry();
  }

  private static void write(final JarOutputStream output, final String name, final byte[] bytes)
      throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(bytes);
    output.closeEntry();
  }

  private void replaceArtifactFile(
      final Fixture fixture, final String artifactId, final Path replacement) {
    fixture.artifacts().stream()
        .filter(artifact -> artifactId.equals(artifact.getArtifactId()))
        .findFirst()
        .orElseThrow()
        .setFile(replacement.toFile());
  }
}
