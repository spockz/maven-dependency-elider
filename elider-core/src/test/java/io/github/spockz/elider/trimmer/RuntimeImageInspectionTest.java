/* WHY: Exercises platform inspection against real, reduced runtime images and archive wrappers. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.module.ModuleDescriptor;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.spi.ToolProvider;
import java.util.zip.GZIPOutputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
final class RuntimeImageInspectionTest {
  private static final String SQL_MODULE = "java.sql";
  private static final String RELEASE_METADATA = "release";
  private static final String MODULE_IMAGE = "lib/modules";

  @Test
  void readsOnlyTheSuppliedRuntimeAndFindsNestedArchiveHomes(@TempDir final Path directory)
      throws IOException {
    final java.util.Optional<ToolProvider> jlink = ToolProvider.findFirst("jlink");
    assumeTrue(jlink.isPresent(), "The test fixture needs the JDK image builder");
    final StringWriter output = new StringWriter();
    final PrintWriter writer = new PrintWriter(output);
    final Path installation = directory.resolve("minimal-jre");
    final int status =
        jlink
            .orElseThrow()
            .run(
                writer,
                writer,
                "--add-modules",
                "java.base",
                "--output",
                installation.toString(),
                "--strip-debug");
    assertThat(status).as(output.toString()).isZero();
    final Path archive = directory.resolve("runtime.zip");
    try (JarOutputStream zip = new JarOutputStream(Files.newOutputStream(archive))) {
      for (final String name : java.util.List.of(RELEASE_METADATA, MODULE_IMAGE)) {
        zip.putNextEntry(new JarEntry("distribution/Contents/Home/" + name));
        Files.copy(installation.resolve(name), zip);
        zip.closeEntry();
      }
      zip.putNextEntry(new JarEntry("distribution/Contents/Home/lib/jrt-fs.jar"));
      zip.write(new byte[] {1});
      zip.closeEntry();
    }
    final JdkPlatformContext.PlatformSnapshot installed =
        JdkPlatformContext.inspectRuntime(installation);
    final Path cache = directory.resolve("runtime-indexes");
    final JdkPlatformContext.PlatformSnapshot compressed =
        JdkPlatformContext.inspectRuntime(archive, cache);
    final Path index;
    try (java.util.stream.Stream<Path> entries = Files.list(cache)) {
      index = entries.findFirst().orElseThrow();
    }
    final java.nio.file.attribute.FileTime oldTime =
        java.nio.file.attribute.FileTime.fromMillis(1_000_000);
    Files.setLastModifiedTime(index, oldTime);
    final JdkPlatformContext.PlatformSnapshot reused =
        JdkPlatformContext.inspectRuntime(installation, cache);
    final java.nio.file.attribute.FileTime reusedTime = Files.getLastModifiedTime(index);
    Files.writeString(index, "incomplete index");
    final JdkPlatformContext.PlatformSnapshot recovered =
        JdkPlatformContext.inspectRuntime(archive, cache);
    final Path tarball = writeTarball(directory, installation);
    final Path truncatedZip = truncateCopy(archive, directory.resolve("truncated.zip"), 1);
    final Path truncatedTarball = truncateCopy(tarball, directory.resolve("truncated.tar.gz"), 8);
    Files.writeString(
        installation.resolve(RELEASE_METADATA),
        "JAVA_VERSION=\"" + installed.runtimeVersion().feature() + ".999\"\n");
    final proguard.classfile.ClassPool table = new JdkApiClassTableReader().read(compressed);
    final ModuleDescriptor optional =
        ModuleDescriptor.newModule("fixture.application")
            .requires(java.util.Set.of(ModuleDescriptor.Requires.Modifier.STATIC), SQL_MODULE)
            .build();
    final ModuleDescriptor required =
        ModuleDescriptor.newModule("fixture.application").requires(SQL_MODULE).build();
    assertAll(
        () -> assertThat(installed.runtimeRelease()).isEqualTo(Runtime.version().feature()),
        () ->
            assertThat(installed.runtimeVersion().feature()).isEqualTo(installed.runtimeRelease()),
        () -> assertThat(compressed.identity()).isEqualTo(installed.identity()),
        () -> assertThat(reused.identity()).isEqualTo(compressed.identity()),
        () -> assertThat(recovered.identity()).isEqualTo(compressed.identity()),
        () -> assertThat(Files.size(index)).isGreaterThan("incomplete index".length()),
        () -> assertThat(reusedTime).isEqualTo(oldTime),
        () ->
            assertThatThrownBy(() -> JdkPlatformContext.inspectRuntime(truncatedZip, cache))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("truncated.zip"),
        () ->
            assertThat(JdkPlatformContext.inspectRuntime(tarball, cache).identity())
                .isEqualTo(compressed.identity()),
        () ->
            assertThatThrownBy(() -> JdkPlatformContext.inspectRuntime(truncatedTarball, cache))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("truncated.tar.gz"),
        () ->
            assertThatThrownBy(() -> JdkPlatformContext.inspectRuntime(installation, cache))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("disagrees with java.base"),
        () ->
            assertThat(compressed.moduleDescriptors())
                .extracting(ModuleDescriptor::name)
                .contains("java.base")
                .doesNotContain(SQL_MODULE),
        () -> assertThat(table.getClass("java/lang/Object")).isNotNull(),
        () -> assertThat(table.getClass("java/sql/Connection")).isNull(),
        () ->
            assertThat(compressed.forApplicationModule(optional).moduleDescriptors())
                .extracting(ModuleDescriptor::name)
                .contains("java.base")
                .doesNotContain(SQL_MODULE),
        () ->
            assertThatThrownBy(() -> compressed.forApplicationModule(required))
                .isInstanceOf(IOException.class)
                .hasMessageContaining(SQL_MODULE));
  }

  @Test
  void refusesMissingAndCorruptImages(@TempDir final Path directory) throws IOException {
    final Path corrupt = Files.writeString(directory.resolve("broken.zip"), "not a ZIP");
    final Path ambiguous = directory.resolve("multiple-images.zip");
    try (JarOutputStream zip = new JarOutputStream(Files.newOutputStream(ambiguous))) {
      for (final String root : java.util.List.of("one/", "two/")) {
        zip.putNextEntry(new JarEntry(root + "lib/modules"));
        zip.write(1);
        zip.closeEntry();
      }
    }
    final Path incomplete = Files.createDirectory(directory.resolve("incomplete-home"));
    Files.writeString(incomplete.resolve(RELEASE_METADATA), "JAVA_VERSION=\"21.0.1\"\n");
    assertAll(
        () ->
            assertThatThrownBy(() -> JdkPlatformContext.inspectRuntime(corrupt))
                .isInstanceOf(IOException.class)
                .hasMessageContaining(corrupt.toString()),
        () ->
            assertThatThrownBy(() -> JdkPlatformContext.inspectRuntime(incomplete))
                .isInstanceOf(IOException.class)
                .hasMessageContaining(MODULE_IMAGE),
        () ->
            assertThatThrownBy(() -> JdkPlatformContext.inspectRuntime(ambiguous))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("multiple runtime images"),
        () ->
            assertThatThrownBy(
                    () -> JdkPlatformContext.inspectRuntime(directory.resolve("missing")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("missing"));
  }

  private static Path writeTarball(final Path directory, final Path installation)
      throws IOException {
    final Path tarball = directory.resolve("runtime.tar.gz");
    try (GZIPOutputStream gzip = new GZIPOutputStream(Files.newOutputStream(tarball));
        TarArchiveOutputStream tar = new TarArchiveOutputStream(gzip, 10_240)) {
      for (final String name : java.util.List.of(RELEASE_METADATA, MODULE_IMAGE)) {
        final Path input = installation.resolve(name);
        tar.putArchiveEntry(tar.createArchiveEntry(input, "distribution/Contents/Home/" + name));
        Files.copy(input, tar);
        tar.closeArchiveEntry();
      }
    }
    return tarball;
  }

  private static Path truncateCopy(final Path original, final Path destination, final int bytes)
      throws IOException {
    Files.copy(original, destination);
    try (FileChannel channel = FileChannel.open(destination, StandardOpenOption.WRITE)) {
      channel.truncate(channel.size() - bytes);
    }
    return destination;
  }
}
