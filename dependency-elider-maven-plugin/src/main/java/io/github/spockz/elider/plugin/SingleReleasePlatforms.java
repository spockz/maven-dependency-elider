/* WHY: Binds single-release analysis to isolated copies of the active runtime platform. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.JdkApiClassTableReader;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.util.List;
import proguard.classfile.ClassPool;

/** Binds single-release analysis to active-runtime platform views. */
final class SingleReleasePlatforms {
  /** One active-runtime snapshot supplies both single-release class tables. */
  private static final int EXPECTED_PLATFORM_SNAPSHOT_COUNT = 1;

  private SingleReleasePlatforms() {}

  /* package */ record JdkClassTables(ClassPool candidate, ClassPool passThrough) {}

  /* package */ static JdkClassTables readJdkClassTables(
      final List<JdkPlatformContext.PlatformSnapshot> snapshots) throws IOException {
    if (snapshots.size() != EXPECTED_PLATFORM_SNAPSHOT_COUNT) {
      throw new IOException("Expected one active runtime platform snapshot");
    }
    final JdkApiClassTableReader reader = new JdkApiClassTableReader();
    final JdkPlatformContext.PlatformSnapshot snapshot = snapshots.getFirst();
    return new JdkClassTables(reader.readFrozen(snapshot), reader.readFrozen(snapshot));
  }

  /* package */ record AnalysisPlatform(
      int targetRelease,
      int runtimeRelease,
      List<JdkPlatformContext.PlatformSnapshot> snapshots,
      JdkClassTables tables) {}

  /* package */ static AnalysisPlatform prepare(final TrimRequest request) throws IOException {
    final TrimExecutionEnvironment executionEnvironment =
        MavenDependencyTrimmer.executionEnvironment(request);
    final List<JdkPlatformContext.PlatformSnapshot> snapshots =
        List.of(MavenPlatformContextHolder.forOperation(request.session()).snapshot());
    return new AnalysisPlatform(
        executionEnvironment.targetRelease(),
        executionEnvironment.runtimeRelease(),
        snapshots,
        readJdkClassTables(snapshots));
  }
}
