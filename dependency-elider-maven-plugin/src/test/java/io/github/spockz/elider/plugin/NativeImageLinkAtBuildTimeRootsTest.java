/* WHY: Proves link-at-build-time inputs resolve only to indexed logical classes. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies LinkAtBuildTime class and indexed path roots. */
/* package */ final class NativeImageLinkAtBuildTimeRootsTest {
  /** Bytecode bodies only mark class entries in the archive inventory. */
  /* package */
  private static final String CONTENT = "bytecode";

  /** Temporary archives keep path identities isolated between cases. */
  /* package */ @TempDir Path tempDir;

  /** JUnit constructs this group to inject its temporary archive directory. */
  /* package */ NativeImageLinkAtBuildTimeRootsTest() {
    super();
  }

  /* package */
  @Test
  void expandsNamedTargetsAcrossLogicalInventory() throws IOException {
    final Path declaring =
        archive(
            "declaring.jar",
            "--link-at-build-time=org.example.pkg -H:LinkAtBuildTime=org.example.pkg");
    final Path exact = archive("exact.jar", "org/example/pkg.class", "org/example/pkg/Exact.class");
    final Path descendant = archive("descendant.jar", "org/example/pkg/Child.class");
    final Path neighbor = archive("neighbor.jar", "org/example/pkgExtra/Neighbor.class");
    final Path versioned =
        archive("versioned.jar", "META-INF/versions/17/org/example/pkg/mr/Versioned.class");
    final NativeImageScanContext context =
        context(declaring, exact, descendant, neighbor, versioned);

    final Path classTarget =
        archive("class-target.jar", "-H:LinkAtBuildTime=org.example.pkg.Exact");
    final List<Set<String>> observed =
        List.of(
            scan(declaring, context).roots(),
            scan(classTarget, context(declaring, exact, descendant, neighbor, versioned)).roots());

    assertThat(observed)
        .containsExactly(
            Set.of(
                "org.example.pkg",
                "org.example.pkg.Exact",
                "org.example.pkg.Child",
                "org.example.pkg.mr.Versioned"),
            Set.of("org.example.pkg.Exact"));
  }

  /* package */
  @Test
  void bareAliasesPinTheIndexedInventory() throws IOException {
    final Path exact = archive("broad-exact.jar", "org/example/pkg.class");
    final Path descendant = archive("broad-descendant.jar", "org/example/pkg/Child.class");
    final Path neighbor = archive("broad-neighbor.jar", "org/example/pkgExtra/Neighbor.class");
    final Path shortForm = archive("broad-short.jar", "-H:LinkAtBuildTime");
    final Path longForm = archive("broad-long.jar", "--link-at-build-time");
    final Set<String> expected =
        Set.of("org.example.pkg", "org.example.pkg.Child", "org.example.pkgExtra.Neighbor");
    final List<Set<String>> observed =
        List.of(
            scan(shortForm, context(shortForm, exact, descendant, neighbor)).roots(),
            scan(longForm, context(longForm, exact, descendant, neighbor)).roots());

    assertThat(observed).containsExactly(expected, expected);
  }

  /* package */
  @Test
  void resolvesPathAliasesAndNormalizationToIndexedArchiveClasses() throws IOException {
    final Path provider = archive("provider.jar", "org/example/provider/FromPath.class");
    final Path symbolicAlias = tempDir.resolve("provider-alias.jar");
    Files.createSymbolicLink(symbolicAlias, provider.getFileName());
    final Path nestedBase = Files.createDirectory(tempDir.resolve("nested-base"));
    final String[] aliases = {
      "-H:LinkAtBuildTimePaths=./provider.jar,provider.jar,provider-alias.jar",
      "--link-at-build-time-paths=" + provider.toAbsolutePath(),
      "-H:LinkAtBuildTimePaths=../provider.jar"
    };
    final List<Set<String>> observed = new ArrayList<>();
    for (int index = 0; index < aliases.length; index++) {
      final Path declaring = archive("path-declaring-" + index + ".jar", aliases[index]);
      final NativeImageScanContext context =
          index == 2 ? contextAt(nestedBase, declaring, provider) : context(declaring, provider);
      final DependencyDynamicRoots.RootScan scan = scan(declaring, context);
      observed.add(scan.roots());
    }

    assertThat(observed)
        .containsExactly(
            Set.of("org.example.provider.FromPath"),
            Set.of("org.example.provider.FromPath"),
            Set.of("org.example.provider.FromPath"));
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
          "-H:LinkAtBuildTimePaths=",
          "--link-at-build-time-paths=",
          "-H:LinkAtBuildTimePaths=provider.jar,missing.jar"
        }) {
      final Path declaring = archive("invalid-" + argument.hashCode() + ".jar", argument);
      final NativeImageScanContext context =
          context(declaring, archive("provider.jar", "org/example/Provider.class"));
      assertThatThrownBy(() -> scan(declaring, context))
          .as(argument)
          .isInstanceOf(IOException.class);
    }
  }

  /* package */
  @Test
  void requiresAnInvocationBaseForRelativePaths() throws IOException {
    final Path declaring = archive("base-required.jar", "-H:LinkAtBuildTimePaths=provider.jar");
    final Path provider = archive("provider.jar", "org/example/Provider.class");
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate("declaring", declaring),
                NativeImageScanContextTestSupport.candidate("provider", provider)),
            null);

    assertThatThrownBy(() -> scan(declaring, context))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("require an invocation base");
  }

  /* package */
  @Test
  void rejectsDirectoriesModulesAndUnindexedArchives() throws IOException {
    final Path directory = Files.createDirectory(tempDir.resolve("directory"));
    final Path module = archive("module.jmod", "org/example/Module.class");
    final Path unindexed = archive("unindexed.jar", "org/example/Unindexed.class");
    for (final String path :
        List.of(directory.toString(), module.toString(), unindexed.toString())) {
      final Path declaring =
          archive("rejected-" + path.hashCode() + ".jar", "-H:LinkAtBuildTimePaths=" + path);
      final NativeImageScanContext context = context(declaring);
      assertThatThrownBy(() -> scan(declaring, context)).as(path).isInstanceOf(IOException.class);
    }
  }

  private Path archive(final String name, final String... entries) throws IOException {
    final List<String> archiveEntries = new ArrayList<>();
    if (entries.length == 1 && entries[0].startsWith("-")) {
      archiveEntries.add(NativeImageScanContextTestSupport.PROPERTIES_ENTRY);
      archiveEntries.add("Args = " + entries[0] + "\n");
    } else {
      for (final String entry : Arrays.asList(entries)) {
        archiveEntries.add(entry);
        archiveEntries.add(CONTENT);
      }
    }
    return NativeImageScanContextTestSupport.jar(
        tempDir, name, archiveEntries.toArray(String[]::new));
  }

  private NativeImageScanContext context(final Path... archives) throws IOException {
    return contextAt(tempDir, archives);
  }

  private NativeImageScanContext contextAt(final Path invocationBase, final Path... archives)
      throws IOException {
    final List<ArtifactFileRef> candidates = new ArrayList<>();
    for (int index = 0; index < archives.length; index++) {
      candidates.add(
          NativeImageScanContextTestSupport.candidate("candidate-" + index, archives[index]));
    }
    return NativeImageScanContext.create(candidates, invocationBase);
  }

  private DependencyDynamicRoots.RootScan scan(
      final Path declaring, final NativeImageScanContext context) throws IOException {
    return DependencyDynamicRoots.scan(declaring, context, Set.of(), true);
  }
}
