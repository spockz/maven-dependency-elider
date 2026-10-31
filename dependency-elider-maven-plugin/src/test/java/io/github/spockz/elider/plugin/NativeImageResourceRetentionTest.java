/* WHY: Verifies a resource pointer keeps the declaration, provider, and dynamic class owner. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Verifies resource-provider artifact retention during Maven pruning. */
/* package */ final class NativeImageResourceRetentionTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** WHY: Every fixture keeps only the declaring application class from its trace. */
  private static final String ENTRY_TRACE = "closure.a.Entry\n";

  /** Creates this focused archive-retention test group. */
  /* package */ NativeImageResourceRetentionTest() {
    super();
  }

  /* package */
  @Test
  void crossArchivePointerRetainsDeclaringProviderAndClassOwner()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-resource-pointer.jar",
            Map.of(
                "META-INF/native-image/test/native-image.properties",
                "Args = -H:ReflectionConfigurationResources=custom.payload\n"));
    final Path provider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-with-resource-descriptor.jar",
            Map.of("custom.payload", "[{\"name\":\"closure.c.Leaf\"}]"));
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", provider);
    final Path trace = temporaryDirectory.resolve("cross-archive-resource.lst");
    Files.writeString(trace, ENTRY_TRACE);

    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                fixture.mavenProject(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));
    final List<Object> observed =
        List.of(
            prepared.dynamicRootInputs().resourceProviderArtifacts(),
            prepared.dynamicRootInputs().classNames(),
            prepared.rawDecision().retainedArtifacts());

    assertThat(observed)
        .containsExactly(
            Set.of(coordinate(fixture, "b")),
            Set.of("closure.c.Leaf"),
            Set.of(coordinate(fixture, "a"), coordinate(fixture, "b"), coordinate(fixture, "c")));
  }

  /* package */
  @Test
  void resourceOnlyPointerRetainsDeclaringAndProviderArchives()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-resource-only-pointer.jar",
            Map.of(
                "META-INF/native-image/test/native-image.properties",
                "Args = -H:ResourceConfigurationResources=custom.payload\n"));
    final Path provider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-with-resource-only-descriptor.jar",
            Map.of(
                "custom.payload", "{\"resources\":{\"includes\":[{\"pattern\":\"assets/.*\"}]}}"),
            Map.of(
                "closure/b/Unused.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Unused.class"))));
    final Path assetProvider =
        appendEntries(
            fixture.snapshot("c").filePath(),
            "c-with-selected-resource.jar",
            Map.of("assets/selected.dat", "selected"));
    replaceArtifactFile(fixture, "a", declaring);
    replaceArtifactFile(fixture, "b", provider);
    replaceArtifactFile(fixture, "c", assetProvider);
    final Path trace = temporaryDirectory.resolve("resource-only-pointer.lst");
    Files.writeString(trace, ENTRY_TRACE);

    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                fixture.mavenProject(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));
    final boolean descriptorProviderHasClass =
        prepared.index().classesByArtifact().entrySet().stream()
            .anyMatch(
                entry ->
                    entry.getKey().coordinate().equals(coordinate(fixture, "b"))
                        && entry.getValue().contains("closure.b.Unused"));

    assertThat(
            List.of(
                prepared.dynamicRootInputs().classNames(),
                prepared.dynamicRootInputs().resourceProviderArtifacts(),
                prepared.rawDecision().retainedArtifacts(),
                descriptorProviderHasClass))
        .containsExactly(
            Set.of(),
            Set.of(coordinate(fixture, "b"), coordinate(fixture, "c")),
            Set.of(coordinate(fixture, "a"), coordinate(fixture, "b"), coordinate(fixture, "c")),
            true);
  }

  /* package */
  @Test
  void autoDiscoveredResourceOnlyDescriptorRetainsItsArchive()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path provider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-with-auto-resource-only-descriptor.jar",
            Map.of(
                "META-INF/native-image/test/resource-config.json",
                "{\"resources\":{\"includes\":[{\"pattern\":\"assets/.*\"}]}}"));
    replaceArtifactFile(fixture, "b", provider);
    final Path trace = temporaryDirectory.resolve("auto-resource-only.lst");
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
                prepared.rawDecision().retainedArtifacts()))
        .containsExactly(Set.of(), Set.of(coordinate(fixture, "a"), coordinate(fixture, "b")));
  }

  /* package */
  @Test
  void autoDiscoveredUnifiedResourceOnlyDescriptorRetainsItsArchive()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, true);
    final Path declaring =
        appendEntries(
            fixture.snapshot("a").filePath(),
            "a-with-unified-resource-only-descriptor.jar",
            Map.of(
                "META-INF/native-image/test/reachability-metadata.json",
                "{\"resources\":[{\"glob\":\"assets/**\"}]}"));
    replaceArtifactFile(fixture, "a", declaring);
    final Path resourceProvider =
        appendEntries(
            fixture.snapshot("b").filePath(),
            "b-with-unified-selected-resource.jar",
            Map.of("assets/selected.dat", "selected"),
            Map.of(
                "closure/b/Unused.class",
                Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Unused.class"))));
    replaceArtifactFile(fixture, "b", resourceProvider);
    final Path trace = temporaryDirectory.resolve("unified-resource-only.lst");
    Files.writeString(trace, ENTRY_TRACE);

    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                fixture.mavenProject(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));

    final ArtifactCoordinate declaringCoordinate = coordinate(fixture, "a");
    final boolean providerHasClass =
        prepared.index().classesByArtifact().entrySet().stream()
            .anyMatch(
                entry ->
                    entry.getKey().coordinate().equals(coordinate(fixture, "b"))
                        && entry.getValue().contains("closure.b.Unused"));
    assertThat(
            List.of(
                prepared.dynamicRootInputs().classNames(),
                prepared.dynamicRootInputs().resourceProviderArtifacts(),
                prepared.dynamicRootInputs().declaringArtifacts().contains(declaringCoordinate),
                prepared
                    .dynamicRootInputs()
                    .scansByPath()
                    .get(declaring.toRealPath())
                    .requiresArtifactRetention(),
                prepared.rawDecision().retainedArtifacts().contains(declaringCoordinate),
                prepared.rawDecision().retainedArtifacts().contains(coordinate(fixture, "b")),
                providerHasClass))
        .containsExactly(Set.of(), Set.of(coordinate(fixture, "b")), true, true, true, true, true);
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
    return NativeImageExternalConfigurationInputTestSupport.appendEntries(
        temporaryDirectory, source, destinationName, additions, classAdditions);
  }

  private static void replaceArtifactFile(
      final Fixture fixture, final String artifactId, final Path replacement) {
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(
        fixture, artifactId, replacement);
  }

  private static ArtifactCoordinate coordinate(final Fixture fixture, final String artifactId) {
    return fixture.coordinate(artifactId);
  }
}
