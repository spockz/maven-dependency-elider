// WHY: Proves same-name classes do not establish equivalence for retained ban references.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.scanner.ProductionBytecodeReferenceScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies conservative provider identity checks for retained ban references. */
final class MavenBanClassProviderClosureTest {
  /** Canonical class name referenced by the consumer fixture. */
  private static final String API_CLASS_NAME = "x.Api";

  /** Internal name used by both fixture classes for their superclass. */
  private static final String OBJECT_INTERNAL_NAME = "java/lang/Object";

  /** Isolates generated provider archives for each test. */
  @TempDir private Path temporaryDirectory;

  /** JUnit constructs this package-private test class. */
  /* default */ MavenBanClassProviderClosureTest() {
    // JUnit needs a constructible test instance.
  }

  @Test
  void rejectsRetainedReferenceWhenAbsentJarHasDifferentSameNameClass() throws Exception {
    final Path absentJar = temporaryDirectory.resolve("absent-provider.jar");
    final Path retainedJar = temporaryDirectory.resolve("retained-provider.jar");
    final byte[] absentApi = apiClassBytes("legacyMethod");
    final byte[] retainedApi = apiClassBytes("replacementMethod");
    writeProviderJar(absentJar, absentApi, null);
    writeProviderJar(retainedJar, retainedApi, consumerClassBytes());
    final Set<String> references =
        new ProductionBytecodeReferenceScanner().scanArchive(retainedJar).referencedClasses();
    final ArtifactCoordinate absentCoordinate =
        MavenBanAuditTestSupport.coordinate("absent-provider");
    final ArtifactCoordinate retainedCoordinate =
        MavenBanAuditTestSupport.coordinate("retained-provider");

    assertThatThrownBy(
            () -> {
              if (Arrays.equals(absentApi, retainedApi)) {
                throw new AssertionError("fixture providers must have different class bytes");
              }
              if (!references.contains(API_CLASS_NAME)) {
                throw new AssertionError("retained bytecode must reference x.Api");
              }
              MavenBanClassProviderClosure.verifyReference(
                  API_CLASS_NAME,
                  "retained archive " + retainedCoordinate + " bytecode",
                  Map.of(API_CLASS_NAME, List.of(absentCoordinate)),
                  Map.of(API_CLASS_NAME, List.of(retainedCoordinate)),
                  Set.of(retainedCoordinate),
                  Set.of());
            })
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("same-name providers are not proven equivalent")
        .hasMessageContaining(absentCoordinate.toString());
  }

  private static byte[] apiClassBytes(final String methodName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "x/Api", null, OBJECT_INTERNAL_NAME, null);
    final MethodVisitor constructor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    constructor.visitCode();
    constructor.visitVarInsn(Opcodes.ALOAD, 0);
    constructor.visitMethodInsn(
        Opcodes.INVOKESPECIAL, OBJECT_INTERNAL_NAME, "<init>", "()V", false);
    constructor.visitInsn(Opcodes.RETURN);
    constructor.visitMaxs(1, 1);
    constructor.visitEnd();
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC, methodName, "()V", null, null);
    method.visitCode();
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 1);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] consumerClassBytes() {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "x/Consumer", null, OBJECT_INTERNAL_NAME, null);
    writer.visitField(Opcodes.ACC_PRIVATE, "api", "Lx/Api;", null, null).visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static void writeProviderJar(
      final Path path, final byte[] apiClass, final byte[] consumerClass) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(path))) {
      zip.putNextEntry(new ZipEntry("x/Api.class"));
      zip.write(apiClass);
      zip.closeEntry();
      if (consumerClass != null) {
        zip.putNextEntry(new ZipEntry("x/Consumer.class"));
        zip.write(consumerClass);
        zip.closeEntry();
      }
    }
  }
}
