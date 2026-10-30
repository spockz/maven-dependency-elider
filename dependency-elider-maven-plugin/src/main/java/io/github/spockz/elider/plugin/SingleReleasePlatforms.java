/* WHY: Binds single-release analysis to frozen compiler and runtime platform
 * views. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.JdkApiClassPoolReader;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import proguard.classfile.ClassPool;

/** Binds single-release analysis to frozen compiler and runtime platform views. */
final class SingleReleasePlatforms {
  private SingleReleasePlatforms() {}

  /* package */ record PlatformPools(ClassPool compiler, ClassPool runtime) {}

  /* package */ static int analysisRelease(
      final TrimRequest request, final Path javaHome, final int runtimeRelease) throws IOException {
    if (!request.policy().trimEnabled()) {
      return runtimeRelease;
    }
    final List<String> compilerOptions =
        MavenCompilerSettings.platformReleaseOptions(request.project(), request.session());
    return TrimPlatform.releaseFromOptions(compilerOptions, javaHome);
  }

  /* package */ static JdkPlatformContext.PlatformSnapshot platformSnapshot(
      final List<JdkPlatformContext.PlatformSnapshot> snapshots, final int release) {
    return snapshots.stream()
        .filter(snapshot -> snapshot.effectiveRelease() == release)
        .findFirst()
        .orElseThrow(
            () ->
                new IllegalStateException("No captured platform snapshot for release " + release));
  }

  /* package */ static PlatformPools readPlatformPools(
      final List<JdkPlatformContext.PlatformSnapshot> snapshots,
      final int compilerRelease,
      final int runtimeRelease)
      throws IOException {
    final JdkApiClassPoolReader reader = new JdkApiClassPoolReader();
    final ClassPool compiler = reader.readFrozen(platformSnapshot(snapshots, compilerRelease));
    final ClassPool runtime =
        runtimeRelease == compilerRelease
            ? compiler
            : reader.readFrozen(platformSnapshot(snapshots, runtimeRelease));
    return new PlatformPools(compiler, runtime);
  }

  /* package */ record AnalysisPlatform(
      Path javaHome,
      int compilerRelease,
      int runtimeRelease,
      List<JdkPlatformContext.PlatformSnapshot> snapshots,
      PlatformPools pools) {}

  /* package */ static AnalysisPlatform prepare(final TrimRequest request) throws IOException {
    final Path javaHome =
        Path.of(System.getProperty(MavenDependencyTrimmer.JAVA_HOME_PROPERTY))
            .toAbsolutePath()
            .normalize();
    final int runtimeRelease = Runtime.version().feature();
    final int release = analysisRelease(request, javaHome, runtimeRelease);
    final List<JdkPlatformContext.PlatformSnapshot> snapshots =
        SingleReleaseTrimInventory.platformSnapshots(javaHome, release, runtimeRelease);
    return new AnalysisPlatform(
        javaHome,
        release,
        runtimeRelease,
        snapshots,
        readPlatformPools(snapshots, release, runtimeRelease));
  }
}
