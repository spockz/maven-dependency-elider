/* WHY: Proves deferred descriptor selectors retain only matching invocation providers and roots. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Tests archive-wide resource selector semantics and physical trimming. */
/* package */ final class NativeImageDescriptorResourceSelectionTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** WHY: Keep the declaring class independent of descriptor roots. */
  private static final String ENTRY_TRACE = "closure.a.Entry\n";

  /** WHY: Provides unrooted bytecode in resource providers. */
  private static final String UNUSED_CLASS = "closure/b/Unused.class";

  /** WHY: Source bytes match the provider's indexed class. */
  private static final String UNUSED_CLASS_FILE = "classes/closure/b/Unused.class";

  /** WHY: Multiple archives use the same descriptor location in exclusion tests. */
  private static final String RESOURCE_CONFIG = "META-INF/native-image/test/resource-config.json";

  /** WHY: The unified glob fixture must resolve an actual classpath resource. */
  private static final String SELECTED_RESOURCE = "assets/selected.dat";

  /** WHY: One service instance prepares the selection acceptance scenarios. */
  private final MavenElisionService service;

  /* package */ NativeImageDescriptorResourceSelectionTest() {
    super();
    service = new MavenElisionService();
  }

  /* package */
  @Test
  void embeddedPatternRetainsOtherwiseUnusedResourceProviderWithIndexedClass()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-embedded-resource-selection.jar",
            Map.of(
                RESOURCE_CONFIG,
                "{\"resources\":{\"includes\":[{\"pattern\":\"runtime/provider\\\\.dat\"}]}}"));
    final Path provider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-with-selected-resource-and-class.jar",
            Map.of("runtime/provider.dat", "selected"),
            Map.of(
                UNUSED_CLASS, Files.readAllBytes(temporaryDirectory.resolve(UNUSED_CLASS_FILE))));
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", provider);
    final Path trace = temporaryDirectory.resolve("embedded-resource-selection.lst");
    Files.writeString(trace, ENTRY_TRACE);

    final ElisionAnalysisModel.PreparedAnalysis prepared =
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
            Set.of(),
            Set.of(fixture.coordinate("b")),
            Set.of(fixture.coordinate("a"), fixture.coordinate("b")),
            true);
  }

  /* package */
  @Test
  void resourceDescriptorPatternsRetainMatchingClassAndTrimUnrelatedClass()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-resource-pattern.jar",
            Map.of(
                RESOURCE_CONFIG,
                "{\"resources\":{\"includes\":[{\"pattern\":"
                    + "\"assets/.*|closure/b/.*\\\\.class\","
                    + "\"condition\":{\"typeReachable\":\"closure.c.Leaf\"}}],"
                    + "\"excludes\":[{\"pattern\":\"assets/private/.*|"
                    + "closure/b/Unused\\\\.class\"}]}}"));
    final Path provider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-with-resource-pattern-provider.jar",
            Map.of("assets/public.dat", "public", "assets/private/secret.dat", "secret"),
            Map.of(
                "closure/b/Middle.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Middle.class")),
                UNUSED_CLASS,
                Files.readAllBytes(temporaryDirectory.resolve(UNUSED_CLASS_FILE))));
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", provider);
    final Path trace = temporaryDirectory.resolve("descriptor-pattern.lst");
    Files.writeString(trace, ENTRY_TRACE);

    final ElisionAnalysisModel.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            MavenElisionServiceEffectiveAnalysisFixtures.options(
                List.of(trace.toFile()), null, true));
    final ElisionAnalysisModel.Analysis analysis = service.finish(prepared);
    final ArtifactTrimRecord providerTrim =
        analysis.trimResult().records().stream()
            .filter(record -> record.coordinate().equals(fixture.coordinate("b")))
            .findFirst()
            .orElseThrow();
    final boolean middlePresent;
    final boolean unusedAbsent;
    try (JarFile output = new JarFile(providerTrim.trimmedPath().toFile())) {
      middlePresent = output.getEntry("closure/b/Middle.class") != null;
      unusedAbsent = output.getEntry(UNUSED_CLASS) == null;
    }

    assertThat(
            List.of(
                prepared.dynamicRootInputs().classNames(),
                prepared.dynamicRootInputs().resourceProviderArtifacts(),
                prepared.rawDecision().retainedArtifacts(),
                providerTrim.retainedClasses(),
                middlePresent,
                unusedAbsent))
        .containsExactly(
            Set.of("closure.b.Middle", "closure.c.Leaf"),
            Set.of(fixture.coordinate("b")),
            Set.of(fixture.coordinate("a"), fixture.coordinate("b"), fixture.coordinate("c")),
            1,
            true,
            true);
  }

  /* package */
  @Test
  void namedModuleGlobDoesNotMatchClasspathAndKeepsConditionRoot()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-named-module-resource-selection.jar",
            Map.of(
                "META-INF/native-image/test/reachability-metadata.json",
                "{\"resources\":[{\"glob\":\"assets/**\","
                    + "\"module\":\"named.module\","
                    + "\"condition\":{\"typeReached\":\"closure.c.Leaf\"}}]}"));
    final Path provider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-with-named-module-resource.jar",
            Map.of(SELECTED_RESOURCE, "selected"),
            Map.of(
                UNUSED_CLASS, Files.readAllBytes(temporaryDirectory.resolve(UNUSED_CLASS_FILE))));
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", provider);
    final Path trace = temporaryDirectory.resolve("named-module-resource-selection.lst");
    Files.writeString(trace, ENTRY_TRACE);

    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                fixture.mavenProject(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));

    assertThat(
            List.of(
                prepared.dynamicRootInputs().classNames(),
                prepared.dynamicRootInputs().resourceProviderArtifacts(),
                prepared.rawDecision().retainedArtifacts()))
        .containsExactly(
            Set.of("closure.c.Leaf"),
            Set.of(),
            Set.of(fixture.coordinate("a"), fixture.coordinate("c")));
  }

  /* package */
  @Test
  void duplicateDescriptorNamesKeepExclusionsScopedToTheirArchive()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path includingArchive =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-positive-resource-config.jar",
            Map.of(
                RESOURCE_CONFIG,
                "{\"resources\":{\"includes\":[{\"pattern\":"
                    + "\"assets/selected\\\\.dat|closure/b/Middle\\\\.class\"}]}}"));
    final Path provider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-with-resource-and-class.jar",
            Map.of(SELECTED_RESOURCE, "selected"),
            Map.of(
                "closure/b/Middle.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Middle.class"))));
    final Path excludingArchive =
        appendEntries(
            fixture.snapshot("c").filePath(),
            "c-with-negative-resource-config.jar",
            Map.of(
                RESOURCE_CONFIG,
                "{\"resources\":{\"includes\":[{\"pattern\":\"never-match\"}],"
                    + "\"excludes\":[{\"pattern\":\"assets/selected\\\\.dat|"
                    + "closure/b/Middle\\\\.class\"}]}}"));
    replaceArtifactFile(fixture, "a", includingArchive);
    replaceArtifactFile(fixture, "b", provider);
    replaceArtifactFile(fixture, "c", excludingArchive);
    final Path trace = temporaryDirectory.resolve("descriptor-exclusion-scope.lst");
    Files.writeString(trace, ENTRY_TRACE);

    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                fixture.mavenProject(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));

    assertThat(
            List.of(
                prepared.dynamicRootInputs().classNames(),
                prepared.dynamicRootInputs().resourceProviderArtifacts()))
        .containsExactly(Set.of("closure.b.Middle"), Set.of(fixture.coordinate("b")));
  }

  private Path appendEntries(
      final Path source,
      final String destinationName,
      final Map<String, String> additions,
      final Map<String, byte[]> classAdditions)
      throws IOException {
    return NativeImageExternalConfigurationInputTestSupport.appendEntries(
        temporaryDirectory, source, destinationName, additions, classAdditions);
  }

  private Path appendEntries(
      final Path source, final String destinationName, final Map<String, String> additions)
      throws IOException {
    return appendEntries(source, destinationName, additions, Map.of());
  }

  private static void replaceArtifactFile(
      final Fixture fixture, final String artifactId, final Path replacement) {
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(
        fixture, artifactId, replacement);
  }
}
