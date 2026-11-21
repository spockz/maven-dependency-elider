/* WHY: Verifies threshold consistency and session reuse in ArchiveClassScanner. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Tests threshold consistency and session reuse in {@link ArchiveClassScanner}. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
/* package */ final class ArchiveClassScannerTest {
  /** Number of extra dummy classes needed to cross the 64-name threshold. */
  private static final int EXTRA_CLASS_COUNT = 64;

  /** Threshold boundary size for direct lookup. */
  private static final int THRESHOLD_SIZE = 64;

  /** Primary versioned class internal name. */
  private static final String CLASS_A = "example/A";

  /** Next frontier class internal name. */
  private static final String CLASS_NEXT = "example/Next";

  /** Common Object reference. */
  private static final String OBJECT_REF = "java.lang.Object";

  /** Common Class reference from method descriptor. */
  private static final String CLASS_REF = "java.lang.Class";

  /** Temporary directory for test archives. */
  @TempDir /* package */ Path temporaryDirectory;

  /* package */
  @Test
  void scanSelectedReturnsIdenticalReferencesAcrossLookupThresholdForMultiReleaseJar()
      throws IOException {
    final Path jar = temporaryDirectory.resolve("mrjar-threshold.jar");
    final Set<String> sixtyFour = new LinkedHashSet<>();
    final Set<String> sixtyFive = new LinkedHashSet<>();
    sixtyFour.add(CLASS_A);
    sixtyFive.add(CLASS_A);

    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      writeClass(output, "example/A.class", CLASS_A, "example/BaseOnly");
      writeClass(output, "META-INF/versions/21/example/A.class", CLASS_A, "example/VersionOnly");
      for (int index = 0; index < EXTRA_CLASS_COUNT; index++) {
        final String internalName = "example/Extra" + index;
        writeClass(output, internalName + ".class", internalName, "java/lang/Object");
        if (sixtyFour.size() < THRESHOLD_SIZE) {
          sixtyFour.add(internalName);
        }
        sixtyFive.add(internalName);
      }
    }

    final Map<String, Set<String>> atThreshold = ArchiveClassScanner.scanSelected(jar, sixtyFour);
    final Map<String, Set<String>> aboveThreshold =
        ArchiveClassScanner.scanSelected(jar, sixtyFive);

    assertAll(
        "Scan results across 64-name threshold",
        () -> assertThat(atThreshold.get(CLASS_A)).isEqualTo(aboveThreshold.get(CLASS_A)),
        () ->
            assertThat(atThreshold.get(CLASS_A))
                .containsExactlyInAnyOrder(OBJECT_REF, CLASS_REF, "example.BaseOnly"),
        () ->
            assertThat(aboveThreshold.get(CLASS_A))
                .containsExactlyInAnyOrder(OBJECT_REF, CLASS_REF, "example.BaseOnly"));
  }

  /* package */
  @Test
  void openSessionScansMultipleFrontiersAcrossSameArchive() throws IOException {
    final Path jar = temporaryDirectory.resolve("session.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      writeClass(output, "example/Root.class", "example/Root", CLASS_NEXT);
      writeClass(output, "example/Next.class", CLASS_NEXT, "example/Leaf");
    }

    try (ArchiveClassScanner.Session session = ArchiveClassScanner.open(jar)) {
      final Map<String, Set<String>> first = session.scanSelected(Set.of("example/Root"));
      final Map<String, Set<String>> second = session.scanSelected(Set.of(CLASS_NEXT));
      final Map<String, Set<String>> empty = session.scanSelected(Set.of());
      assertAll(
          "Session multi-frontier scans",
          () ->
              assertThat(first.get("example/Root"))
                  .containsExactlyInAnyOrder(OBJECT_REF, CLASS_REF, "example.Next"),
          () ->
              assertThat(second.get(CLASS_NEXT))
                  .containsExactlyInAnyOrder(OBJECT_REF, CLASS_REF, "example.Leaf"),
          () -> assertThat(empty).isEmpty());
    }
  }

  private static void writeClass(
      final JarOutputStream output,
      final String entryName,
      final String internalName,
      final String referencedInternalName)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "ref", "()Ljava/lang/Class;", null, null);
    method.visitCode();
    method.visitLdcInsn(org.objectweb.asm.Type.getObjectType(referencedInternalName));
    method.visitInsn(Opcodes.ARETURN);
    method.visitMaxs(1, 0);
    method.visitEnd();
    writer.visitEnd();
    output.putNextEntry(new JarEntry(entryName));
    output.write(writer.toByteArray());
    output.closeEntry();
  }
}
