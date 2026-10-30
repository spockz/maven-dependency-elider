/* WHY: Proves link-at-build-time inputs resolve only to indexed logical classes. */

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.NativeImageLinkAtBuildTimeTestSupport.archive;
import static io.github.spockz.elider.plugin.NativeImageLinkAtBuildTimeTestSupport.context;
import static io.github.spockz.elider.plugin.NativeImageLinkAtBuildTimeTestSupport.scan;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies LinkAtBuildTime class and indexed path roots. */
/* package */ final class NativeImageLinkAtBuildTimeRootsTest {
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
            tempDir,
            "declaring.jar",
            "--link-at-build-time=org.example.pkg -H:LinkAtBuildTime=org.example.pkg");
    final Path exact =
        archive(tempDir, "exact.jar", "org/example/pkg.class", "org/example/pkg/Exact.class");
    final Path descendant = archive(tempDir, "descendant.jar", "org/example/pkg/Child.class");
    final Path neighbor = archive(tempDir, "neighbor.jar", "org/example/pkgExtra/Neighbor.class");
    final Path versioned =
        archive(
            tempDir, "versioned.jar", "META-INF/versions/17/org/example/pkg/mr/Versioned.class");
    final NativeImageScanContext context =
        context(tempDir, declaring, exact, descendant, neighbor, versioned);

    final Path classTarget =
        archive(tempDir, "class-target.jar", "-H:LinkAtBuildTime=org.example.pkg.Exact");
    final List<Set<String>> observed =
        List.of(
            scan(declaring, context).roots(),
            scan(classTarget, context(tempDir, declaring, exact, descendant, neighbor, versioned))
                .roots());

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
    final Path exact = archive(tempDir, "broad-exact.jar", "org/example/pkg.class");
    final Path descendant = archive(tempDir, "broad-descendant.jar", "org/example/pkg/Child.class");
    final Path neighbor =
        archive(tempDir, "broad-neighbor.jar", "org/example/pkgExtra/Neighbor.class");
    final Path shortForm = archive(tempDir, "broad-short.jar", "-H:LinkAtBuildTime");
    final Path longForm = archive(tempDir, "broad-long.jar", "--link-at-build-time");
    final Set<String> expected =
        Set.of("org.example.pkg", "org.example.pkg.Child", "org.example.pkgExtra.Neighbor");
    final List<Set<String>> observed =
        List.of(
            scan(shortForm, context(tempDir, shortForm, exact, descendant, neighbor)).roots(),
            scan(longForm, context(tempDir, longForm, exact, descendant, neighbor)).roots());

    assertThat(observed).containsExactly(expected, expected);
  }

  /* package */
  @Test
  void acceptsUnicodeJavaIdentifiersInIndexedTypes() throws IOException {
    final Path declaring =
        archive(tempDir, "unicode-declaring.jar", "--link-at-build-time=org.example.\\u0394");
    final Path provider =
        archive(
            tempDir, "unicode-provider.jar", "org/example/Δ.class", "org/example/Δ/Child.class");

    assertThat(scan(declaring, context(tempDir, declaring, provider)).roots())
        .containsExactlyInAnyOrder("org.example.Δ", "org.example.Δ.Child");
  }
}
