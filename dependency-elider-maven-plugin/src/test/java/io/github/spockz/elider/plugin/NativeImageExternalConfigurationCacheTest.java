/* WHY: Proves file descriptor bytes participate in both trim cache identities. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Verifies external descriptor cache identities. */
/* package */ final class NativeImageExternalConfigurationCacheTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Creates this focused cache identity test group. */
  /* package */ NativeImageExternalConfigurationCacheTest() {
    super();
  }

  /* package */
  @Test
  void changedExternalDescriptorMissesLegacyTrimCacheWhenRootsStayEqual()
      throws IOException, MojoFailureException {
    final NativeImageExternalConfigurationCacheTestSupport.CacheRun run = cacheRun();
    final ElisionAnalysisModel.Analysis first = run.service().finish(run.first());
    final ElisionAnalysisModel.PreparedAnalysis warmPrepared =
        prepareLegacy(run.fixture(), run.trace());
    final ElisionAnalysisModel.Analysis warm = run.service().finish(warmPrepared);
    NativeImageExternalConfigurationCacheTestSupport.changeWhitespaceOnly(run.descriptor());
    final ElisionAnalysisModel.PreparedAnalysis secondPrepared =
        prepareLegacy(run.fixture(), run.trace());
    final ElisionAnalysisModel.Analysis second = run.service().finish(secondPrepared);

    NativeImageExternalConfigurationCacheTestSupport.assertLegacyBehavior(
        first, warm, second, run.first(), secondPrepared);
  }

  /* package */
  @Test
  void changedExternalDescriptorMissesEffectiveTrimCacheWhenRootsStayEqual()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false);
    fixture.addVersionedClassToC();
    final Path declaring =
        NativeImageExternalConfigurationCacheTestSupport.declaringWithPointer(
            temporaryDirectory, fixture, "effective-pointer.jar");
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "a", declaring);
    final Path descriptor = temporaryDirectory.resolve("cache-descriptor.payload");
    Files.writeString(descriptor, NativeImageExternalConfigurationCacheTestSupport.reflection());
    final Path trace =
        NativeImageExternalConfigurationCacheTestSupport.writeTrace(temporaryDirectory);
    final ServiceOperation first = operation(fixture, trace, null, true);
    final TrimResult firstTrim = trimEffective(first);
    final ServiceOperation warm = operation(fixture, trace, null, true);
    final TrimResult warmTrim = trimEffective(warm);
    NativeImageExternalConfigurationCacheTestSupport.changeWhitespaceOnly(descriptor);
    final ServiceOperation second = operation(fixture, trace, null, true);
    final TrimResult secondTrim = trimEffective(second);

    NativeImageExternalConfigurationCacheTestSupport.assertEffectiveBehavior(
        firstTrim, warmTrim, secondTrim, first, second);
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void changedExternalDescriptorAfterEffectiveAnalysisPreservesPriorGeneration()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false);
    final Path declaring =
        NativeImageExternalConfigurationCacheTestSupport.declaringWithPointer(
            temporaryDirectory, fixture, "effective-freshness-pointer.jar");
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "a", declaring);
    final Path descriptor = temporaryDirectory.resolve("cache-descriptor.payload");
    Files.writeString(descriptor, NativeImageExternalConfigurationCacheTestSupport.reflection());
    final Path trace =
        NativeImageExternalConfigurationCacheTestSupport.writeTrace(temporaryDirectory);
    final ServiceOperation operation = operation(fixture, trace, null, true);
    final ElisionAnalysisModel.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    final TrimResult published = MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    assertThat(published.records())
        .as("the preservation assertions must observe an actual generated archive")
        .isNotEmpty();
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final byte[] priorManifest = Files.readAllBytes(manifest);
    final List<String> priorOutputs = outputSnapshot(published.records());
    NativeImageExternalConfigurationCacheTestSupport.changeWhitespaceOnly(descriptor);

    assertThatThrownBy(() -> MavenDependencyTrimmer.trimEffectiveOutputs(effective))
        .hasMessageContaining("Native-image input content changed after preparation");

    assertAll(
        "a consumed descriptor change after analysis cannot replace the cached output generation",
        () -> assertManifestUnchanged(manifest, priorManifest),
        () -> assertOutputsUnchanged(published.records(), priorOutputs),
        () -> assertDescriptorWasConsumed(operation, descriptor));
  }

  private static void assertManifestUnchanged(final Path manifest, final byte[] priorManifest)
      throws IOException {
    assertThat(Files.readAllBytes(manifest)).containsExactly(priorManifest);
  }

  private static void assertOutputsUnchanged(
      final List<ArtifactTrimRecord> records, final List<String> priorOutputs) throws IOException {
    assertThat(outputSnapshot(records)).containsExactlyElementsOf(priorOutputs);
  }

  private static void assertDescriptorWasConsumed(
      final ServiceOperation operation, final Path descriptor) {
    assertThat(operation.prepared().dynamicRootInputs().consumedInputs())
        .anySatisfy(
            input ->
                assertThat(input.logicalPath()).isEqualTo(descriptor.toAbsolutePath().normalize()));
  }

  private static List<String> outputSnapshot(final List<ArtifactTrimRecord> records)
      throws IOException {
    final List<String> snapshots = new ArrayList<>();
    for (final ArtifactTrimRecord record : records) {
      snapshots.add(
          record.trimmedPath() + ":" + ArtifactDigests.read(record.trimmedPath()).sha256());
    }
    return List.copyOf(snapshots);
  }

  private NativeImageExternalConfigurationCacheTestSupport.CacheRun cacheRun()
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false);
    final Path declaring =
        NativeImageExternalConfigurationCacheTestSupport.declaringWithPointer(
            temporaryDirectory, fixture, "legacy-pointer.jar");
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "a", declaring);
    final Path descriptor = temporaryDirectory.resolve("cache-descriptor.payload");
    Files.writeString(descriptor, NativeImageExternalConfigurationCacheTestSupport.reflection());
    final Path trace =
        NativeImageExternalConfigurationCacheTestSupport.writeTrace(temporaryDirectory);
    final Path sourceDirectory =
        Files.createDirectories(temporaryDirectory.resolve("legacy-source/closure/a"));
    Files.writeString(
        sourceDirectory.resolve("Entry.java"), "package closure.a; public class Entry {}\n");
    final Build build = fixture.mavenProject().getBuild();
    build.setSourceDirectory(temporaryDirectory.resolve("legacy-source").toString());
    fixture.mavenProject().addCompileSourceRoot(build.getSourceDirectory());
    final MavenElisionService service = new MavenElisionService();
    return new NativeImageExternalConfigurationCacheTestSupport.CacheRun(
        fixture, descriptor, trace, service, prepareLegacy(fixture, trace));
  }

  private ElisionAnalysisModel.PreparedAnalysis prepareLegacy(
      final Fixture fixture, final Path trace) throws IOException, MojoFailureException {
    return new MavenElisionService()
        .prepare(
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
                    MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
                    MavenPluginDescriptorFixtures.releasedProducerResolution()),
                new ElisionAnalysisModel.DynamicRootOptions(false)));
  }
}
