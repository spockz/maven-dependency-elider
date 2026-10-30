/* WHY: Ensures recognized directory children cannot evade descriptor schema validation. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Checks recognized descriptor path failures before root scanning. */
/* package */ final class NativeImageConfigurationDirectoryMalformedEntryTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** The recognized filename used to test logical-parent sibling lookup. */
  private static final String PREDEFINED_DESCRIPTOR = "predefined-classes-config.json";

  /** Prefix that identifies each option-bearing test archive. */
  private final String archivePrefix;

  /* package */ NativeImageConfigurationDirectoryMalformedEntryTest() {
    super();
    archivePrefix = "declaring";
  }

  /* package */
  @Test
  void validatesOnePhysicalFileUnderEveryRecognizedSchemaKind() throws IOException {
    final Path directory = Files.createDirectories(temporaryDirectory.resolve("shared-configs"));
    final Path shared =
        Files.writeString(
            directory.resolve("payload.json"),
            NativeImageScanContextTestSupport.reflection("org.example.Type"));
    Files.createSymbolicLink(directory.resolve("a-reflect-config.json"), shared);
    Files.createSymbolicLink(directory.resolve("z-proxy-config.json"), shared);
    final Path archive = declaringArchive("shared-configs");

    assertThatThrownBy(() -> scan(archive))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("proxy");
  }

  /* package */
  @Test
  void recognizedDescriptorDirectoryFailsAsNonRegular() throws IOException {
    final Path directory = Files.createDirectories(temporaryDirectory.resolve("directory-configs"));
    Files.createDirectory(directory.resolve("reflect-config.json"));
    final Path archive = declaringArchive("directory-configs");

    assertThatThrownBy(() -> scan(archive))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("not a regular file");
  }

  /* package */
  @Test
  void brokenRecognizedDescriptorSymlinkFailsAsNonRegular() throws IOException {
    final Path directory = Files.createDirectories(temporaryDirectory.resolve("broken-configs"));
    Files.createSymbolicLink(
        directory.resolve("reflect-config.json"), directory.resolve("missing-payload.json"));
    final Path archive = declaringArchive("broken-configs");

    assertThatThrownBy(() -> scan(archive))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("not a regular file");
  }

  /* package */
  @Test
  void readsPredefinedSiblingDataFromEveryLogicalParent() throws IOException {
    final Path parent = Files.createDirectories(temporaryDirectory.resolve("predefined-parent"));
    final Path child = Files.createDirectories(parent.resolve("child"));
    final String hash = "0123456789abcdef0123456789abcdef";
    final Path sharedDescriptor = child.resolve(PREDEFINED_DESCRIPTOR);
    Files.writeString(sharedDescriptor, predefinedDocument(hash));
    Files.createSymbolicLink(parent.resolve(PREDEFINED_DESCRIPTOR), sharedDescriptor);
    writeClassData(parent, hash, "org/example/ParentGenerated");
    writeClassData(child, hash, "org/example/ChildGenerated");
    final Path archive =
        declaringArchive(
            "-H:ConfigurationFileDirectories=predefined-parent,predefined-parent/child\n",
            "predefined-parents.jar");

    final DependencyDynamicRoots.RootScan scan = scan(archive);

    org.assertj.core.api.Assertions.assertThat(scan.roots())
        .contains("org.example.ParentGenerated", "org.example.ChildGenerated");
  }

  /* package */
  @Test
  void missingPredefinedSiblingInSecondLogicalParentFails() throws IOException {
    final Path parent = Files.createDirectories(temporaryDirectory.resolve("predefined-missing"));
    final Path child = Files.createDirectories(parent.resolve("child"));
    final String hash = "fedcba9876543210fedcba9876543210";
    final Path sharedDescriptor = child.resolve(PREDEFINED_DESCRIPTOR);
    Files.writeString(sharedDescriptor, predefinedDocument(hash));
    Files.createSymbolicLink(parent.resolve(PREDEFINED_DESCRIPTOR), sharedDescriptor);
    writeClassData(parent, hash, "org/example/ParentGenerated");
    final Path archive =
        declaringArchive(
            "-H:ConfigurationFileDirectories=predefined-missing,predefined-missing/child\n",
            "predefined-missing-sibling.jar");

    assertThatThrownBy(() -> scan(archive))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unresolved predefined class hash");
  }

  private Path declaringArchive(final String directory) throws IOException {
    return declaringArchive(
        "-H:ConfigurationFileDirectories=" + directory + "\n", directory + ".jar");
  }

  private Path declaringArchive(final String args, final String name) throws IOException {
    return NativeImageScanContextTestSupport.jar(
        temporaryDirectory,
        archivePrefix + "-" + name,
        NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
        "Args = " + args);
  }

  private DependencyDynamicRoots.RootScan scan(final Path archive) throws IOException {
    final ArtifactFileRef candidate =
        NativeImageScanContextTestSupport.candidate("declaring", archive);
    final NativeImageScanContext context =
        NativeImageScanContext.create(List.of(candidate), temporaryDirectory);
    return DependencyDynamicRoots.scan(archive, context, Set.of(), true);
  }

  private static String predefinedDocument(final String hash) {
    return "[{\"type\":\"agent-extracted\",\"classes\":[{\"hash\":\"" + hash + "\"}]}]";
  }

  private static void writeClassData(
      final Path descriptorParent, final String hash, final String internalName)
      throws IOException {
    final Path directory =
        Files.createDirectories(descriptorParent.resolve("agent-extracted-predefined-classes"));
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    Files.write(directory.resolve(hash + ".classdata"), writer.toByteArray());
  }
}
