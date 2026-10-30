/* WHY: Keeps directory-option assertions focused on scanned roots and invalidation evidence. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** Shared assertions for bounded Native Image directory scans. */
/* package */ final class NativeImageConfigurationDirectoriesTestSupport {
  private NativeImageConfigurationDirectoriesTestSupport() {
    throw new AssertionError("static fixture holder");
  }

  /* package */ static void assertDirectDirectoryScan(final DependencyDynamicRoots.RootScan scan) {
    final int directorySnapshots =
        (int)
            scan.consumedInputs().stream()
                .filter(input -> "configuration-directory-membership".equals(input.role()))
                .count();
    final List<String> descriptorNames =
        scan.consumedInputs().stream()
            .filter(input -> input.role().startsWith("descriptor:"))
            .map(input -> input.logicalPath().getFileName().toString())
            .sorted()
            .toList();
    assertThat(List.of(scan.roots(), directorySnapshots, descriptorNames))
        .containsExactly(
            Set.of("org.example.A", "org.example.B"),
            1,
            List.of("a-reflect-config.json", "b-reflect-config.json"));
  }

  /* package */ static void assertEmptyDirectoryScan(final DependencyDynamicRoots.RootScan scan) {
    assertThat(
            List.of(
                scan.roots(),
                scan.consumedInputs().stream().map(NativeImageConsumedInput::role).toList()))
        .containsExactly(Set.of(), List.of("configuration-directory-membership"));
  }

  /* package */ static void assertMembershipChangeFails(
      final DependencyDynamicRoots.RootScan scan) {
    assertThatThrownBy(() -> NativeImageConsumedInput.verifyAll(scan.consumedInputs()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("changed after preparation");
  }

  /* package */ static void assertAliasRetargetFails(
      final DependencyDynamicRoots.RootScan scan, final Path alias, final Path replacement)
      throws IOException {
    final long snapshots =
        scan.consumedInputs().stream()
            .filter(input -> "configuration-directory-membership".equals(input.role()))
            .count();
    assertThat(snapshots).isEqualTo(2);
    Files.delete(alias);
    Files.createSymbolicLink(alias, replacement);
    assertMembershipChangeFails(scan);
  }

  /* package */ static void assertResourceRootScan(
      final DependencyDynamicRoots.RootScan scan, final Path first, final Path second)
      throws IOException {
    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(
            Set.of("org.example.First", "org.example.Second"),
            Set.of(first.toRealPath(), second.toRealPath()));
  }

  /* package */ static void assertDescriptorRelativeRootScan(
      final DependencyDynamicRoots.RootScan scan, final Path provider) throws IOException {
    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(
            Set.of("org.example.Relative", "org.example.Repeated"), Set.of(provider.toRealPath()));
  }

  /* package */ static void assertEmptyResourceRoot(final DependencyDynamicRoots.RootScan scan) {
    assertThat(List.of(scan.roots(), scan.resourceProviders())).containsExactly(Set.of(), Set.of());
  }
}
