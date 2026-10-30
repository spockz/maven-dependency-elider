/* WHY: Proves file descriptor bytes participate in both trim cache identities. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
    final MavenElisionService.Analysis first = run.service().finish(run.first());
    final MavenElisionService.PreparedAnalysis warmPrepared =
        prepareLegacy(run.fixture(), run.trace());
    final MavenElisionService.Analysis warm = run.service().finish(warmPrepared);
    NativeImageExternalConfigurationCacheTestSupport.changeWhitespaceOnly(run.descriptor());
    final MavenElisionService.PreparedAnalysis secondPrepared =
        prepareLegacy(run.fixture(), run.trace());
    final MavenElisionService.Analysis second = run.service().finish(secondPrepared);

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
    final MavenDependencyTrimmer.TrimResult firstTrim = trimEffective(first);
    final ServiceOperation warm = operation(fixture, trace, null, true);
    final MavenDependencyTrimmer.TrimResult warmTrim = trimEffective(warm);
    NativeImageExternalConfigurationCacheTestSupport.changeWhitespaceOnly(descriptor);
    final ServiceOperation second = operation(fixture, trace, null, true);
    final MavenDependencyTrimmer.TrimResult secondTrim = trimEffective(second);

    NativeImageExternalConfigurationCacheTestSupport.assertEffectiveBehavior(
        firstTrim, warmTrim, secondTrim, first, second);
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

  private MavenElisionService.PreparedAnalysis prepareLegacy(
      final Fixture fixture, final Path trace) throws IOException, MojoFailureException {
    return new MavenElisionService()
        .prepare(
            fixture.mavenProject(),
            new MavenElisionService.AnalysisOptions(
                List.of(trace.toFile()),
                List.of(),
                null,
                null,
                true,
                true,
                List.of(),
                false,
                List.of(),
                false,
                true,
                false));
  }
}
