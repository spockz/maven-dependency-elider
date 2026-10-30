/* WHY: Proves path-list parsing, canonical identity, and unsupported archive rejection. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies LinkAtBuildTimePaths resolves only indexed archive identities. */
/* package */ final class NativeImageLinkAtBuildTimePathsTest {
  /** Reused archive name keeps relative path fixtures identical. */
  /* package */
  private static final String PROVIDER_ARCHIVE_NAME = "provider.jar";

  /** Exact option spelling used for relative path-list cases. */
  /* package */
  private static final String PATHS_OPTION = "-H:LinkAtBuildTimePaths=";

  /** Temporary archives keep path identities isolated between cases. */
  /* package */ @TempDir Path tempDir;

  /** JUnit constructs this group to inject its temporary archive directory. */
  /* package */ NativeImageLinkAtBuildTimePathsTest() {
    super();
  }

  /* package */
  @Test
  void resolvesPathAliasesAndNormalizationToIndexedArchiveClasses() throws IOException {
    final Path provider =
        NativeImageLinkAtBuildTimeTestSupport.archive(
            tempDir, PROVIDER_ARCHIVE_NAME, "org/example/provider/FromPath.class");
    final Path symbolicAlias = tempDir.resolve("provider-alias.jar");
    Files.createSymbolicLink(symbolicAlias, provider.getFileName());
    final Path nestedBase = Files.createDirectory(tempDir.resolve("nested-base"));
    final String[] aliases = {
      PATHS_OPTION
          + String.join(
              File.pathSeparator,
              "./" + PROVIDER_ARCHIVE_NAME,
              PROVIDER_ARCHIVE_NAME,
              "provider-alias.jar"),
      "--link-at-build-time-paths=" + provider.toAbsolutePath(),
      PATHS_OPTION + "../" + PROVIDER_ARCHIVE_NAME
    };
    final List<Set<String>> observed = new ArrayList<>();
    for (int index = 0; index < aliases.length; index++) {
      final Path declaring =
          NativeImageLinkAtBuildTimeTestSupport.archive(
              tempDir, "path-declaring-" + index + ".jar", aliases[index]);
      final NativeImageScanContext scanContext =
          index == 2
              ? NativeImageLinkAtBuildTimeTestSupport.context(nestedBase, declaring, provider)
              : NativeImageLinkAtBuildTimeTestSupport.context(tempDir, declaring, provider);
      observed.add(NativeImageLinkAtBuildTimeTestSupport.scan(declaring, scanContext).roots());
    }

    assertThat(observed)
        .containsExactly(
            Set.of("org.example.provider.FromPath"),
            Set.of("org.example.provider.FromPath"),
            Set.of("org.example.provider.FromPath"));
  }

  /* package */
  @Test
  void capturesEachNormalizedPathAliasInConsumedInputs() throws IOException {
    final Path provider =
        NativeImageLinkAtBuildTimeTestSupport.archive(
            tempDir, "snapshot-provider.jar", "org/example/provider/FromPath.class");
    final Path alias = tempDir.resolve("snapshot-alias.jar");
    Files.createSymbolicLink(alias, provider.getFileName());
    final Path declaring =
        NativeImageLinkAtBuildTimeTestSupport.archive(
            tempDir,
            "snapshot-declaring.jar",
            PATHS_OPTION
                + String.join(
                    File.pathSeparator,
                    provider.getFileName().toString(),
                    alias.getFileName().toString()));

    final DependencyDynamicRoots.RootScan scan =
        NativeImageLinkAtBuildTimeTestSupport.scan(
            declaring, NativeImageLinkAtBuildTimeTestSupport.context(tempDir, declaring, provider));

    assertThat(scan.consumedInputs())
        .extracting(NativeImageConsumedInput::logicalPath)
        .containsExactlyInAnyOrder(
            provider.toAbsolutePath().normalize(), alias.toAbsolutePath().normalize());
  }

  /* package */
  @Test
  void rejectsEmptyAndMalformedPathInputs() throws IOException {
    for (final String argument :
        new String[] {
          "-H:LinkAtBuildTime=",
          "--link-at-build-time=",
          "-H:LinkAtBuildTime=org.example.Bad-Name",
          "--link-at-build-time=org.example.One,,org.example.Two",
          "-H:LinkAtBuildTimePaths",
          PATHS_OPTION,
          "--link-at-build-time-paths=",
          PATHS_OPTION + String.join(File.pathSeparator, PROVIDER_ARCHIVE_NAME, "missing.jar")
        }) {
      final Path declaring =
          NativeImageLinkAtBuildTimeTestSupport.archive(
              tempDir, "invalid-" + argument.hashCode() + ".jar", argument);
      final NativeImageScanContext scanContext =
          NativeImageLinkAtBuildTimeTestSupport.context(
              tempDir,
              declaring,
              NativeImageLinkAtBuildTimeTestSupport.archive(
                  tempDir, PROVIDER_ARCHIVE_NAME, "org/example/Provider.class"));
      assertThatThrownBy(() -> NativeImageLinkAtBuildTimeTestSupport.scan(declaring, scanContext))
          .as(argument)
          .isInstanceOf(IOException.class);
    }
  }

  /* package */
  @Test
  void requiresAnInvocationBaseForRelativePaths() throws IOException {
    final Path declaring =
        NativeImageLinkAtBuildTimeTestSupport.archive(
            tempDir, "base-required.jar", PATHS_OPTION + PROVIDER_ARCHIVE_NAME);
    final Path provider =
        NativeImageLinkAtBuildTimeTestSupport.archive(
            tempDir, PROVIDER_ARCHIVE_NAME, "org/example/Provider.class");
    final NativeImageScanContext scanContext =
        NativeImageLinkAtBuildTimeTestSupport.context(null, declaring, provider);

    assertThatThrownBy(() -> NativeImageLinkAtBuildTimeTestSupport.scan(declaring, scanContext))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("require an invocation base");
  }

  /* package */
  @Test
  void rejectsDirectoriesModulesAndUnindexedArchives() throws IOException {
    final Path directory = Files.createDirectory(tempDir.resolve("directory"));
    final Path module =
        NativeImageLinkAtBuildTimeTestSupport.archive(
            tempDir, "module.jmod", "org/example/Module.class");
    final Path unindexed =
        NativeImageLinkAtBuildTimeTestSupport.archive(
            tempDir, "unindexed.jar", "org/example/Unindexed.class");
    for (final String path :
        List.of(directory.toString(), module.toString(), unindexed.toString())) {
      final Path declaring =
          NativeImageLinkAtBuildTimeTestSupport.archive(
              tempDir, "rejected-" + path.hashCode() + ".jar", PATHS_OPTION + path);
      assertThatThrownBy(
              () ->
                  NativeImageLinkAtBuildTimeTestSupport.scan(
                      declaring, NativeImageLinkAtBuildTimeTestSupport.context(tempDir, declaring)))
          .as(path)
          .isInstanceOf(IOException.class);
    }
  }

  /* package */
  @Test
  void rejectsIndexedJmodBehindJarSymlink() throws IOException {
    final Path module =
        NativeImageLinkAtBuildTimeTestSupport.archive(
            tempDir, "indexed-module.jmod", "org/example/Module.class");
    final Path alias = tempDir.resolve("indexed-module-alias.jar");
    Files.createSymbolicLink(alias, module.getFileName());
    final Path declaring =
        NativeImageLinkAtBuildTimeTestSupport.archive(
            tempDir, "indexed-module-declaring.jar", PATHS_OPTION + alias);

    assertThatThrownBy(
            () ->
                NativeImageLinkAtBuildTimeTestSupport.scan(
                    declaring,
                    NativeImageLinkAtBuildTimeTestSupport.context(tempDir, declaring, module)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("module paths are unsupported");
  }
}
