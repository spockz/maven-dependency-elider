/* WHY: Verifies prepared analysis captures archive and mutable platform inputs at its boundary. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;
import proguard.classfile.LibraryClass;
import proguard.classfile.LibraryMethod;
import proguard.classfile.kotlin.UnsupportedKotlinMetadata;

/** Tests immutable inputs for lazy prepared reference graphs. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidDuplicateLiterals",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.LawOfDemeter"
})
class PreparedAnalysisContextTest {
  /** Isolates generated archive fixtures. */
  @TempDir Path temporaryDirectory;

  /** Supplies only the platform superclass required by generated fixtures. */
  private static ClassPool objectPool;

  @BeforeAll
  static void readObjectClass() throws IOException {
    objectPool = new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 21);
  }

  @Test
  @DisplayName("ADR-0003: rooted and rootless contexts report null or missing siblings explicitly")
  void siblingValidationReportsNullAndMissingEntriesBeforeArchiveRead() throws Exception {
    final Path candidateJar =
        writeClassJar("candidate.jar", Map.of("fixture/Root", simpleClass("fixture/Root", null)));
    final Path missingSibling = temporaryDirectory.resolve("missing-sibling.jar");
    final List<List<Path>> invalidLibraries =
        List.of(Arrays.asList((Path) null), List.of(missingSibling));
    final List<List<String>> roots = List.of(List.of(), List.of("fixture.Root"));

    for (final List<Path> invalidLibrary : invalidLibraries) {
      for (final List<String> retainedRoots : roots) {
        assertThatThrownBy(
                () ->
                    new DependencyJarTrimmer()
                        .analyze(candidateJar, invalidLibrary, objectPool, retainedRoots))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Library classpath entry does not exist: " + invalidLibrary.get(0));
      }
    }
  }

  @Test
  @DisplayName(
      "ADR-0003: prepared contexts freeze platform class definitions before rootless queries")
  void preparedContextIgnoresPlatformDefinitionMutationsAfterPreparation() throws Exception {
    final Path candidateJar =
        writeClassJar(
            "platform-context-candidate.jar",
            Map.of("fixture/PlatformRoot", methodReferenceClass()));
    final Path platformJar =
        writeClassJar("platform-context-added.jar", Map.of("fixture/Added", platformMethodClass()));
    final ClassPool addedClasses = ArchiveSnapshot.read(platformJar, true).newClassPool(true);
    final ClassPool mutablePlatformPool = new ClassPool(objectPool);
    mutablePlatformPool.addClass(addedClasses.getClass("fixture/Added"));
    final DependencyJarTrimmer.PreparedAnalysis prepared =
        new DependencyJarTrimmer()
            .prepareInternal(
                candidateJar,
                List.of(),
                mutablePlatformPool,
                false,
                Set.of(),
                ArchiveSnapshot::read);

    assertThat(prepared.analyze(List.of()).retainedClasses()).contains("fixture/PlatformRoot");
    assertThat(prepared.referenceGraphBuilt()).isFalse();
    ((LibraryClass) mutablePlatformPool.getClass("fixture/Added")).methods = new LibraryMethod[0];

    assertThat(prepared.analyze(List.of("fixture.PlatformRoot")).retainedClasses())
        .containsExactly("fixture/PlatformRoot");
    assertThat(prepared.referenceGraphBuilt()).isTrue();
  }

  @Test
  @DisplayName("ADR-0003: platform pools reject definitions outside the LibraryClass API contract")
  void platformPoolRejectsProgramClassEntries() throws Exception {
    final Path candidateJar =
        writeClassJar(
            "candidate-program-api.jar", Map.of("fixture/Root", simpleClass("fixture/Root", null)));
    final Path platformJar =
        writeClassJar("program-api.jar", Map.of("fixture/Api", simpleClass("fixture/Api", null)));
    final ClassPool programPool = ArchiveSnapshot.read(platformJar, true).newClassPool(false);

    assertThatThrownBy(
            () ->
                new DependencyJarTrimmer()
                    .prepareInternal(
                        candidateJar,
                        List.of(),
                        programPool,
                        false,
                        Set.of(),
                        ArchiveSnapshot::read))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Platform class pool entries must be LibraryClass instances");
  }

  @Test
  @DisplayName("ADR-0003: platform pools reject Kotlin metadata with an explicit diagnostic")
  void platformPoolRejectsKotlinMetadataEntries() throws Exception {
    final Path candidateJar =
        writeClassJar(
            "metadata-candidate.jar", Map.of("fixture/Root", simpleClass("fixture/Root", null)));
    final Path platformJar =
        writeClassJar("metadata-api.jar", Map.of("fixture/Api", simpleClass("fixture/Api", null)));
    final ClassPool platformPool = ArchiveSnapshot.read(platformJar, true).newClassPool(true);
    ((LibraryClass) platformPool.getClass("fixture/Api")).kotlinMetadata =
        new UnsupportedKotlinMetadata(1, new int[0], 0, null, null);

    assertThatThrownBy(
            () ->
                new TrimAnalysisSession(new DependencyJarTrimmer())
                    .prepareWithUnchangedPassThroughLibraries(
                        candidateJar, List.of(), platformPool, Set.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(
            "Platform class pool entries with Kotlin metadata are unsupported: fixture/Api");
  }

  private Path writeClassJar(final String fileName, final Map<String, byte[]> classes)
      throws IOException {
    final Path jarPath = temporaryDirectory.resolve(fileName);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jarPath))) {
      for (final Map.Entry<String, byte[]> entry : classes.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey() + ".class"));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return jarPath;
  }

  private static byte[] simpleClass(final String name, final String fieldType) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    if (fieldType != null) {
      writer
          .visitField(Opcodes.ACC_PUBLIC, "reference", "L" + fieldType + ";", null, null)
          .visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] methodReferenceClass() {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "fixture/PlatformRoot", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "call", "()V", null, null);
    method.visitCode();
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/Added", "invoke", "()V", false);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] platformMethodClass() {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "fixture/Added", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "invoke", "()V", null, null);
    method.visitCode();
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }
}
