/* WHY: Proves ServiceLoader roots reach output decisions and physical archive trimming. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Checks provider retention and unrelated class pruning. */
/* package */ final class NativeImageServiceLoaderTrimTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Service descriptor path for the fixture's provider. */
  private final String serviceDescriptor;

  /** Unrelated provider class pruned by the service-root fixture. */
  private static final String UNRELATED_PROVIDER_CLASS = "closure/b/Unused.class";

  /* package */ NativeImageServiceLoaderTrimTest() {
    super();
    serviceDescriptor = "META-INF/services/closure.a.Entry";
  }

  /* package */
  @Test
  void featureRootsRetainProviderAndPhysicallyTrimUnrelatedClasses()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-service-feature.jar",
            Map.of(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:+UseServiceLoaderFeature\n"),
            Map.of());
    final Path descriptor =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-service-descriptor.jar",
            Map.of(serviceDescriptor, "closure.c.Leaf\n"),
            Map.of());
    final Path provider =
        appendEntries(
            fixture.snapshot("c").filePath(),
            "c-service-provider.jar",
            Map.of(),
            Map.of(
                UNRELATED_PROVIDER_CLASS,
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Unused.class"))));
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", descriptor);
    replaceArtifactFile(fixture, "c", provider);
    final Path trace = temporaryDirectory.resolve("service-feature-trace.lst");
    Files.writeString(trace, "closure.a.Entry\n");

    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            new MavenElisionService.AnalysisOptions(
                List.of(trace.toFile()),
                List.of(),
                null,
                null,
                false,
                true,
                List.of(),
                false,
                List.of(),
                false,
                true,
                false));
    final MavenElisionService.Analysis analysis = service.finish(prepared);
    final ArtifactTrimRecord providerTrim =
        analysis.trimRecords().stream()
            .filter(record -> record.coordinate().equals(fixture.coordinate("c")))
            .findFirst()
            .orElseThrow();
    final boolean providerPresent;
    final boolean unrelatedClassRemoved;
    try (JarFile output = new JarFile(providerTrim.trimmedPath().toFile())) {
      providerPresent = output.getEntry("closure/c/Leaf.class") != null;
      unrelatedClassRemoved = output.getEntry(UNRELATED_PROVIDER_CLASS) == null;
    }

    assertThat(
            List.of(
                prepared.dynamicRootInputs().classNames(),
                prepared.rawDecision().retainedArtifacts(),
                analysis.effectiveDecision().retainedArtifacts(),
                providerTrim.totalClasses(),
                providerTrim.retainedClasses(),
                providerPresent,
                unrelatedClassRemoved))
        .containsExactly(
            Set.of("closure.a.Entry", "closure.c.Leaf"),
            Set.of(fixture.coordinate("a"), fixture.coordinate("b"), fixture.coordinate("c")),
            Set.of(fixture.coordinate("a"), fixture.coordinate("b"), fixture.coordinate("c")),
            2,
            1,
            true,
            true);
  }

  private static void replaceArtifactFile(
      final Fixture fixture, final String artifactId, final Path replacement) {
    fixture.artifacts().stream()
        .filter(artifact -> artifact.getArtifactId().equals(artifactId))
        .findFirst()
        .orElseThrow()
        .setFile(replacement.toFile());
  }

  private Path appendEntries(
      final Path source,
      final String destinationName,
      final Map<String, String> textEntries,
      final Map<String, byte[]> byteEntries)
      throws IOException {
    final Path destination = temporaryDirectory.resolve(destinationName);
    try (JarFile archive = new JarFile(source.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(destination))) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        copyEntry(archive, output, entries.nextElement());
      }
      for (final Map.Entry<String, String> entry : textEntries.entrySet()) {
        write(
            output,
            entry.getKey(),
            entry.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
      }
      for (final Map.Entry<String, byte[]> entry : byteEntries.entrySet()) {
        write(output, entry.getKey(), entry.getValue());
      }
    }
    return destination;
  }

  @Test
  void effectiveFeatureRootsReachOwnerScansWithoutConservativeFallback() throws Exception {
    final Fixture fixture = fixtureWithRuntimeFirstAndResourceOnlySecond();
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "effective-service-feature.jar",
            Map.of(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:+UseServiceLoaderFeature\n"),
            Map.of("closure/a/Unused.class", unreferencedFirstArtifactClass()));
    final Path descriptor =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "effective-service-descriptor.jar",
            Map.of("META-INF/services/closure.a.Extra", "closure.c.Leaf\n"),
            Map.of());
    final Path provider =
        appendEntries(
            fixture.snapshot("c").filePath(),
            "effective-service-provider.jar",
            Map.of(),
            Map.of(
                "closure/b/Unused.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Unused.class"))));
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", descriptor);
    replaceArtifactFile(fixture, "c", provider);
    final Path trace = temporaryDirectory.resolve("effective-service-trace.lst");
    Files.writeString(trace, "closure.a.Entry\n");

    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis raw =
        service.prepare(
            fixture.mavenProject(),
            new MavenElisionService.AnalysisOptions(
                List.of(trace.toFile()),
                List.of(),
                null,
                null,
                false,
                true,
                List.of(),
                false,
                List.of(),
                false,
                true,
                false));
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionServiceEffectiveAnalysisFixtures.graphPairWithAncestorEdges(fixture, false);
    final EffectiveGraphPolicy.Evaluation evaluation =
        EffectiveGraphPolicy.evaluatePair(pair, raw.rawDecision());
    final MavenElisionGraphBinding.Result binding =
        new MavenElisionGraphBinding.Result(
            evaluation,
            raw.graphBinding().inventoryFingerprint(),
            raw.graphBinding().operationFingerprint(),
            pair);
    final MavenElisionService.PreparedAnalysis prepared =
        MavenElisionServiceEffectiveAnalysisFixtures.withBinding(raw, binding);
    final MavenElisionService.EffectiveAnalysis effective = service.finishAnalysis(prepared);
    final MavenDependencyTrimmer.TrimResult trimmed =
        MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    final ArtifactTrimRecord providerTrim =
        trimmed.records().stream()
            .filter(item -> item.coordinate().equals(fixture.coordinate("c")))
            .findFirst()
            .orElseThrow();
    final ArtifactTrimRecord declaringTrim =
        trimmed.records().stream()
            .filter(item -> item.coordinate().equals(fixture.coordinate("a")))
            .findFirst()
            .orElseThrow();
    final boolean interfacePresent;
    final boolean unrelatedInterfaceClassRemoved;
    try (JarFile output = new JarFile(declaringTrim.trimmedPath().toFile())) {
      interfacePresent = output.getEntry("closure/a/Extra.class") != null;
      unrelatedInterfaceClassRemoved = output.getEntry("closure/a/Unused.class") == null;
    }
    final boolean providerPresent;
    final boolean unrelatedProviderClassRemoved;
    try (JarFile output = new JarFile(providerTrim.trimmedPath().toFile())) {
      providerPresent = output.getEntry("closure/c/Leaf.class") != null;
      unrelatedProviderClassRemoved = output.getEntry(UNRELATED_PROVIDER_CLASS) == null;
    }
    assertThat(
            List.of(
                prepared.dynamicRootInputs().classNames(),
                prepared.dynamicRootInputs().scansByPath().get(declaring).roots(),
                effective.trimAnalysis().candidateRoots().get(fixture.coordinate("a")),
                effective.trimAnalysis().candidateRoots().get(fixture.coordinate("c")),
                effective.effectiveDecision().retainedArtifacts(),
                interfacePresent,
                unrelatedInterfaceClassRemoved,
                providerPresent,
                unrelatedProviderClassRemoved))
        .containsExactly(
            Set.of("closure.a.Extra", "closure.c.Leaf"),
            Set.of("closure.a.Extra"),
            Set.of("closure.a.Entry", "closure.a.Extra"),
            Set.of("closure.c.Leaf"),
            Set.of(fixture.coordinate("a"), fixture.coordinate("b"), fixture.coordinate("c")),
            true,
            true,
            true,
            true);
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

  private byte[] unreferencedFirstArtifactClass() throws IOException {
    final Path source = temporaryDirectory.resolve("unreferenced/Unused.java");
    final Path classes = temporaryDirectory.resolve("unreferenced-classes");
    Files.createDirectories(source.getParent());
    Files.writeString(source, "package closure.a; class Unused {}\n");
    io.github.spockz.elider.test.CompilationFixtureSupport.compile(classes, List.of(source));
    return Files.readAllBytes(classes.resolve("closure/a/Unused.class"));
  }

  private static void write(final JarOutputStream output, final String name, final byte[] bytes)
      throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(bytes);
    output.closeEntry();
  }
}
