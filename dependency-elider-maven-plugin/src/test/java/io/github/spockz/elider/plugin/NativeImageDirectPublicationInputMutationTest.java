/* WHY: Proves changed external Native Image inputs cannot publish staged direct outputs. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Guards the last direct-output publication boundary for external inputs. */
/* package */ final class NativeImageDirectPublicationInputMutationTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Replacement type changes descriptor bytes after staging. */
  private final String changedClass;

  /* package */ NativeImageDirectPublicationInputMutationTest() {
    super();
    changedClass = "closure.d.Ancestor";
  }

  /* package */ record PublicationObservation(String failure, List<Boolean> outputPathsExist) {}

  @Test
  void descriptorMutationAfterStagingPreventsOutputPublication()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, false);
    final Path declaring =
        NativeImageExternalConfigurationInputTestSupport.appendEntries(
            temporaryDirectory,
            fixture.snapshot("a").filePath(),
            "a-direct-publication-pointer.jar",
            java.util.Map.of(
                "META-INF/native-image/test/native-image.properties",
                "Args = -H:ReflectionConfigurationFiles=direct-reflection.payload\n"));
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "a", declaring);
    final Path descriptor = temporaryDirectory.resolve("direct-reflection.payload");
    Files.writeString(descriptor, NativeImageScanContextTestSupport.reflection("closure.c.Leaf"));
    final Path trace = temporaryDirectory.resolve("direct-publication-trace.lst");
    Files.writeString(trace, "closure.a.Entry\n");
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                fixture.mavenProject(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));

    final PublicationObservation observation =
        publishAfterMutation(prepared, descriptor, changedClass);

    assertThat(observation)
        .isEqualTo(
            new PublicationObservation(
                "Native-image input content changed after preparation: "
                    + descriptor.toAbsolutePath().normalize(),
                prepared.resolvedSnapshots().stream().map(snapshot -> false).toList()));
  }

  private static PublicationObservation publishAfterMutation(
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Path descriptor,
      final String changedClass)
      throws IOException {
    final TrimRequest request =
        TrimRequestFactory.fromPreparedAnalysis(
            prepared,
            prepared.resolvedSnapshots().stream()
                .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
                .collect(java.util.stream.Collectors.toSet()),
            prepared.pruningRequiredClasses());
    final int release = Runtime.version().feature();
    try (JdkPlatformContext platform =
        new JdkPlatformContext(Path.of(System.getProperty("java.home")))) {
      final DirectTrimPreparation.PreparedDirectTrim plan =
          DirectTrimPreparation.prepare(request, release, release, platform);
      DirectTrimAnalysis.analyze(plan);
      Files.writeString(descriptor, NativeImageScanContextTestSupport.reflection(changedClass));
      try {
        DirectArchiveStaging.publish(plan);
        return publicationObservation(prepared, null);
      } catch (final IOException exception) {
        return publicationObservation(prepared, exception.getMessage());
      }
    }
  }

  private static PublicationObservation publicationObservation(
      final ElisionAnalysisModel.PreparedAnalysis prepared, final String failure) {
    return new PublicationObservation(
        failure,
        prepared.resolvedSnapshots().stream()
            .map(
                snapshot ->
                    Files.exists(TrimPaths.outputPath(prepared.project(), snapshot.coordinate())))
            .toList());
  }
}
