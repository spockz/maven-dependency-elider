/* WHY: Proves package initialization roots preserve classes in trimmed dependency archives. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;

/** Verifies invocation-wide initialization roots through real archive trimming. */
/* package */ final class NativeImageInitializationRetentionTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** WHY: Supplies the exact package-root directive embedded in the fixture archive. */
  /* package */
  private final String initializationArgument;

  /* package */
  NativeImageInitializationRetentionTest() {
    super();
    initializationArgument = "Args = --initialize-at-build-time=closure\n";
  }

  /* package */
  @Test
  void packageInitializationRootsKeepClassesDuringArchiveTrimming() throws Exception {
    final Fixture fixture = fixtureWithRuntimeA();
    final Map<String, byte[]> additions =
        Map.of("unused/DropA.class", emptyClassBytes("unused/DropA"));
    final Path declaring =
        NativeImageExternalConfigurationInputTestSupport.appendEntries(
            temporaryDirectory,
            fixture.snapshot("a").filePath(),
            "a-with-package-initialization.jar",
            Map.of("META-INF/native-image/test/native-image.properties", initializationArgument),
            additions);
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "a", declaring);
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(
        fixture,
        "b",
        addUnrelatedClass(
            fixture.snapshot("b").filePath(), "b-with-unrelated-class.jar", "unused/DropB"));
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(
        fixture,
        "c",
        addUnrelatedClass(
            fixture.snapshot("c").filePath(), "c-with-unrelated-class.jar", "unused/DropC"));
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(
        fixture,
        "d",
        addUnrelatedClass(
            fixture.snapshot("d").filePath(), "d-with-unrelated-class.jar", "unused/DropD"));
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(
        fixture,
        "e",
        addUnrelatedClass(
            fixture.snapshot("e").filePath(), "e-with-unrelated-class.jar", "unused/DropE"));
    final Path trace = temporaryDirectory.resolve("package-initialization.lst");
    Files.writeString(trace, "closure.a.Entry\n");

    final ElisionAnalysisModel.Analysis analysis =
        new MavenElisionService()
            .analyze(
                fixture.mavenProject(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));
    final Map<ArtifactCoordinate, Set<String>> retainedClasses =
        new java.util.concurrent.ConcurrentHashMap<>();
    for (final ArtifactTrimRecord record : analysis.trimResult().records()) {
      retainedClasses.put(record.coordinate(), classNames(record.trimmedPath()));
    }

    assertThat(retainedClasses)
        .containsExactlyInAnyOrderEntriesOf(
            Map.of(
                coordinate(fixture, "a"), Set.of("closure.a.Entry", "closure.a.Extra"),
                coordinate(fixture, "b"), Set.of("closure.b.Middle", "closure.b.Unused"),
                coordinate(fixture, "c"), Set.of("closure.c.Leaf"),
                coordinate(fixture, "d"), Set.of("closure.d.Ancestor"),
                coordinate(fixture, "e"), Set.of("closure.e.Leaf")));
  }

  private Path addUnrelatedClass(final Path source, final String name, final String internalName)
      throws IOException {
    return NativeImageExternalConfigurationInputTestSupport.appendEntries(
        temporaryDirectory,
        source,
        name,
        Map.of(),
        Map.of(internalName + ".class", emptyClassBytes(internalName)));
  }

  private static Set<String> classNames(final Path archivePath) throws IOException {
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      return archive.stream()
          .filter(entry -> !entry.isDirectory() && entry.getName().endsWith(".class"))
          .map(
              entry -> entry.getName().substring(0, entry.getName().length() - 6).replace('/', '.'))
          .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }
  }

  private static ArtifactCoordinate coordinate(final Fixture fixture, final String artifactId) {
    return fixture.coordinate(artifactId);
  }
}
