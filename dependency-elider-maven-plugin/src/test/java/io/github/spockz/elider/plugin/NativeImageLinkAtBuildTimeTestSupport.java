/* WHY: Shares indexed archive construction and scanning across link-option tests. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/** Builds small indexed inventories for LinkAtBuildTime behavior tests. */
/* package */ final class NativeImageLinkAtBuildTimeTestSupport {
  /** Bytecode bodies only mark class entries in the archive inventory. */
  /* package */
  static final String CONTENT = "bytecode";

  private NativeImageLinkAtBuildTimeTestSupport() {
    throw new AssertionError("static link-option test support");
  }

  /* package */ static Path archive(
      final Path directory, final String name, final String... entries) throws IOException {
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
        directory, name, archiveEntries.toArray(String[]::new));
  }

  /* package */ static NativeImageScanContext context(
      final Path invocationBase, final Path... archives) throws IOException {
    final List<ArtifactFileRef> candidates = new ArrayList<>();
    for (int index = 0; index < archives.length; index++) {
      candidates.add(
          NativeImageScanContextTestSupport.candidate("candidate-" + index, archives[index]));
    }
    return NativeImageScanContext.create(candidates, invocationBase);
  }

  /* package */ static DependencyDynamicRoots.RootScan scan(
      final Path declaring, final NativeImageScanContext context) throws IOException {
    return DependencyDynamicRoots.scan(declaring, context, Set.of(), true);
  }
}
