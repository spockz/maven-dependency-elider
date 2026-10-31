/* WHY: Verifies bounded directory discovery, membership tracking, and classpath root lookup. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Exercises Native Image configuration directories. */
/* package */ final class NativeImageConfigurationDirectoriesTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Identifies the archive that declares each directory option. */
  private final String declaringArtifact;

  /* package */ NativeImageConfigurationDirectoriesTest() {
    super();
    declaringArtifact = "declaring";
  }

  /* package */
  @Test
  void readsSortedDirectDescriptorsAndDeduplicatesDirectoryAliases() throws IOException {
    final Path directory = Files.createDirectories(temporaryDirectory.resolve("configs"));
    Files.writeString(
        directory.resolve("b-reflect-config.json"),
        NativeImageScanContextTestSupport.reflection("org.example.B"));
    Files.writeString(
        directory.resolve("a-reflect-config.json"),
        NativeImageScanContextTestSupport.reflection("org.example.A"));
    final Path nested = Files.createDirectories(directory.resolve("nested"));
    Files.writeString(
        nested.resolve("reflect-config.json"),
        NativeImageScanContextTestSupport.reflection("org.example.Nested"));
    final Path declaring =
        declaringJar("-H:ConfigurationFileDirectories=configs,./configs\n", "directory-direct.jar");
    final DependencyDynamicRoots.RootScan scan = scanFiles(declaring);

    NativeImageConfigurationDirectoriesTestSupport.assertDirectDirectoryScan(scan);
  }

  /* package */
  @Test
  void existingEmptyDirectoryIsAcceptedAndSnapshotted() throws IOException {
    Files.createDirectories(temporaryDirectory.resolve("empty-configs"));
    final Path declaring =
        declaringJar("-H:ConfigurationFileDirectories=empty-configs\n", "empty-directory.jar");
    final DependencyDynamicRoots.RootScan scan = scanFiles(declaring);

    NativeImageConfigurationDirectoriesTestSupport.assertEmptyDirectoryScan(scan);
  }

  /* package */
  @Test
  void missingFileDirectoryFailsClearly() throws IOException {
    final Path declaring =
        declaringJar("-H:ConfigurationFileDirectories=missing-configs\n", "missing-directory.jar");
    assertThatThrownBy(() -> scanFiles(declaring))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("configuration directory is missing");
  }

  /* package */
  @Test
  void emptyDirectoryValueFailsClearly() throws IOException {
    final Path emptyValue =
        declaringJar("-H:ConfigurationFileDirectories=\n", "empty-directory-value.jar");
    assertThatThrownBy(() -> scanFiles(emptyValue))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("has no paths");
  }

  /* package */
  @Test
  void descriptorOrderIsDeterministicOnFailure() throws IOException {
    final Path directory = Files.createDirectories(temporaryDirectory.resolve("ordered-configs"));
    Files.writeString(directory.resolve("z-reflect-config.json"), "[{\"unknown\":true}]");
    Files.writeString(directory.resolve("a-reflect-config.json"), "[{\"unknown\":true}]");
    final Path ordered =
        declaringJar("-H:ConfigurationFileDirectories=ordered-configs\n", "ordered-directory.jar");

    assertThatThrownBy(() -> scanFiles(ordered))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("a-reflect-config.json")
        .hasMessageNotContaining("z-reflect-config.json");
  }

  /* package */
  @Test
  void directoryMembershipChangesInvalidateItsPreparedSnapshot() throws IOException {
    final Path directory = Files.createDirectories(temporaryDirectory.resolve("mutable-configs"));
    Files.writeString(
        directory.resolve("reflect-config.json"),
        NativeImageScanContextTestSupport.reflection("org.example.Existing"));
    final Path declaring =
        declaringJar("-H:ConfigurationFileDirectories=mutable-configs\n", "mutable-directory.jar");
    final DependencyDynamicRoots.RootScan scan = scanFiles(declaring);
    Files.writeString(
        directory.resolve("serialization-config.json"),
        "{\"types\":[{\"name\":\"org.example.Added\"}],\"lambdaCapturingTypes\":[]}");

    NativeImageConfigurationDirectoriesTestSupport.assertMembershipChangeFails(scan);
  }

  /* package */
  @Test
  void canonicalDirectoryAliasesEachKeepTheirLogicalSnapshot() throws IOException {
    final Path directory = Files.createDirectories(temporaryDirectory.resolve("canonical-configs"));
    Files.writeString(
        directory.resolve("reflect-config.json"),
        NativeImageScanContextTestSupport.reflection("org.example.Existing"));
    final Path alias = temporaryDirectory.resolve("alias-configs");
    Files.createSymbolicLink(alias, directory);
    final Path declaring =
        declaringJar(
            "-H:ConfigurationFileDirectories=canonical-configs,alias-configs\n",
            "canonical-aliases.jar");
    final DependencyDynamicRoots.RootScan scan = scanFiles(declaring);
    NativeImageConfigurationDirectoriesTestSupport.assertAliasRetargetFails(
        scan, alias, Files.createDirectories(temporaryDirectory.resolve("new-target")));
  }

  private Path declaringJar(final String args, final String name) throws IOException {
    return NativeImageScanContextTestSupport.jar(
        temporaryDirectory,
        name,
        NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
        "Args = " + args);
  }

  private DependencyDynamicRoots.RootScan scanFiles(final Path declaring) throws IOException {
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(candidate(declaringArtifact, declaring)), temporaryDirectory);
    return DependencyDynamicRoots.scan(declaring, context);
  }

  private ArtifactFileRef candidate(final String artifact, final Path path) throws IOException {
    return NativeImageScanContextTestSupport.candidate(artifact, path);
  }
}
