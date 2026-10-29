/* WHY: Keeps signature-polymorphic call-site tests separate from general archive closure tests. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.test.CompilationFixtureSupport;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** JUnit package-private fixtures verify valid signature-polymorphic calls. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.AtLeastOneConstructor"})
class SignaturePolymorphicPositiveTest {
  /** Binary name used by the generated descriptors. */
  private static final String DESCRIPTOR_ONLY = "fixture/DescriptorOnly";

  /** Class-file path for the descriptor-only fixture. */
  private static final String DESCRIPTOR_ONLY_CLASS = DESCRIPTOR_ONLY + ".class";

  /** The default access modifier allows JUnit to inject this temporary directory. */
  @TempDir Path temporaryDirectory;

  @Test
  @DisplayName("ADR-0003: MethodHandle signature-polymorphic call sites resolve and execute")
  void methodHandleSignaturePolymorphicCallsRemainValidAfterTrimming() throws Exception {
    final Path sourceDirectory = temporaryDirectory.resolve("method-handle-src/fixture");
    final Path outputDirectory = temporaryDirectory.resolve("method-handle-classes");
    Files.createDirectories(sourceDirectory);
    Files.createDirectories(outputDirectory);
    final Path sourceFile = sourceDirectory.resolve("SignaturePolymorphic.java");
    Files.writeString(
        sourceFile,
        "package fixture; "
            + "public final class SignaturePolymorphic { "
            + "public static int run() throws Throwable { "
            + "java.lang.invoke.MethodHandle handle = java.lang.invoke.MethodHandles.lookup()"
            + ".findStatic(SignaturePolymorphic.class, \"target\", "
            + "java.lang.invoke.MethodType.methodType(int.class, "
            + "DescriptorOnly.class, int.class)); "
            + "return (int) handle.invokeExact((DescriptorOnly) null, 41); } "
            + "private static int target(DescriptorOnly ignored, int value) "
            + "{ return value + 1; } } "
            + "final class DescriptorOnly {}");
    CompilationFixtureSupport.compile(outputDirectory, List.of(sourceFile));
    final Path candidateJar =
        SignaturePolymorphicTestSupport.writeClassJar(
            temporaryDirectory,
            "method-handle.jar",
            Map.of(
                "fixture/SignaturePolymorphic.class",
                Files.readAllBytes(outputDirectory.resolve("fixture/SignaturePolymorphic.class")),
                DESCRIPTOR_ONLY_CLASS,
                Files.readAllBytes(outputDirectory.resolve("fixture/DescriptorOnly.class"))));

    final DependencyJarTrimmer.TrimAnalysis analysis =
        SignaturePolymorphicTestSupport.analyze(
            candidateJar, List.of("fixture.SignaturePolymorphic"));
    final boolean retained =
        analysis
            .retainedClasses()
            .containsAll(Set.of("fixture/SignaturePolymorphic", DESCRIPTOR_ONLY));
    final Path retainedJar =
        SignaturePolymorphicTestSupport.writeRetainedJar(
            temporaryDirectory, candidateJar, analysis.retainedClasses());
    try (URLClassLoader loader =
        new URLClassLoader(
            new java.net.URL[] {retainedJar.toUri().toURL()},
            ClassLoader.getPlatformClassLoader())) {
      final boolean executed =
          loader.loadClass("fixture.SignaturePolymorphic").getMethod("run").invoke(null).equals(42);
      assertThat(List.of(retained, executed)).containsExactly(true, true);
    }
  }

  @Test
  @DisplayName("ADR-0003: signature-polymorphic call-site descriptor alone retains its type")
  void signaturePolymorphicDescriptorAloneRootsItsType() throws Throwable {
    final ClassWriter callerWriter = new ClassWriter(0);
    callerWriter.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC,
        "fixture/SignaturePolymorphicOnlyDescriptor",
        null,
        "java/lang/Object",
        null);
    final org.objectweb.asm.MethodVisitor caller =
        callerWriter.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "call",
            "(Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;",
            null,
            new String[] {"java/lang/Throwable"});
    caller.visitCode();
    caller.visitVarInsn(Opcodes.ALOAD, 0);
    caller.visitInsn(Opcodes.ACONST_NULL);
    caller.visitMethodInsn(
        Opcodes.INVOKEVIRTUAL,
        "java/lang/invoke/MethodHandle",
        "invokeExact",
        "(Lfixture/DescriptorOnly;)Ljava/lang/Object;",
        false);
    caller.visitInsn(Opcodes.ARETURN);
    caller.visitMaxs(2, 1);
    caller.visitEnd();
    callerWriter.visitEnd();
    final boolean descriptorIsNotClassConstant =
        !ClassFileConstantPool.containsClassConstant(callerWriter.toByteArray(), DESCRIPTOR_ONLY);

    final ClassWriter descriptorWriter = new ClassWriter(0);
    descriptorWriter.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, DESCRIPTOR_ONLY, null, "java/lang/Object", null);
    descriptorWriter.visitEnd();
    final Path candidateJar =
        SignaturePolymorphicTestSupport.writeClassJar(
            temporaryDirectory,
            "descriptor-only.jar",
            Map.of(
                "fixture/SignaturePolymorphicOnlyDescriptor.class",
                callerWriter.toByteArray(),
                DESCRIPTOR_ONLY_CLASS,
                descriptorWriter.toByteArray()));

    final DependencyJarTrimmer.TrimAnalysis analysis =
        SignaturePolymorphicTestSupport.analyze(
            candidateJar, List.of("fixture.SignaturePolymorphicOnlyDescriptor"));
    final boolean retained =
        analysis
            .retainedClasses()
            .containsAll(Set.of("fixture/SignaturePolymorphicOnlyDescriptor", DESCRIPTOR_ONLY));
    final Path retainedJar =
        SignaturePolymorphicTestSupport.writeRetainedJar(
            temporaryDirectory, candidateJar, analysis.retainedClasses());
    try (URLClassLoader loader =
        new URLClassLoader(
            new java.net.URL[] {retainedJar.toUri().toURL()},
            ClassLoader.getPlatformClassLoader())) {
      final Class<?> descriptorClass = loader.loadClass(DESCRIPTOR_ONLY.replace('/', '.'));
      final java.lang.invoke.MethodHandle target =
          java.lang.invoke.MethodHandles.dropArguments(
              java.lang.invoke.MethodHandles.constant(Object.class, "signature-polymorphic"),
              0,
              descriptorClass);
      final Object execution =
          loader
              .loadClass("fixture.SignaturePolymorphicOnlyDescriptor")
              .getMethod("call", java.lang.invoke.MethodHandle.class)
              .invoke(null, target);
      assertThat(
              List.of(
                  descriptorIsNotClassConstant,
                  retained,
                  "signature-polymorphic".equals(execution)))
          .containsExactly(true, true, true);
    }
  }

  @Test
  @DisplayName("ADR-0003: VarHandle get, set, and CAS call sites resolve and execute")
  void varHandleSignaturePolymorphicCallsRemainValidAfterTrimming() throws Exception {
    final Path sourceDirectory = temporaryDirectory.resolve("var-handle-src/fixture");
    final Path outputDirectory = temporaryDirectory.resolve("var-handle-classes");
    Files.createDirectories(sourceDirectory);
    Files.createDirectories(outputDirectory);
    final Path sourceFile = sourceDirectory.resolve("VarHandlePolymorphic.java");
    Files.writeString(
        sourceFile,
        "package fixture; "
            + "public final class VarHandlePolymorphic { "
            + "private static DescriptorOnly value; "
            + "public static DescriptorOnly run() throws Throwable { "
            + "java.lang.invoke.VarHandle handle = java.lang.invoke.MethodHandles.lookup()"
            + ".findStaticVarHandle(VarHandlePolymorphic.class, \"value\", DescriptorOnly.class); "
            + "DescriptorOnly first = new DescriptorOnly(); "
            + "handle.set(first); "
            + "if (!handle.compareAndSet(first, new DescriptorOnly())) "
            + "throw new AssertionError(); "
            + "return (DescriptorOnly) handle.get(); } } "
            + "final class DescriptorOnly {}");
    CompilationFixtureSupport.compile(outputDirectory, List.of(sourceFile));
    final Path candidateJar =
        SignaturePolymorphicTestSupport.writeClassJar(
            temporaryDirectory,
            "var-handle.jar",
            Map.of(
                "fixture/VarHandlePolymorphic.class",
                Files.readAllBytes(outputDirectory.resolve("fixture/VarHandlePolymorphic.class")),
                "fixture/DescriptorOnly.class",
                Files.readAllBytes(outputDirectory.resolve("fixture/DescriptorOnly.class"))));

    final DependencyJarTrimmer.TrimAnalysis analysis =
        SignaturePolymorphicTestSupport.analyze(
            candidateJar, List.of("fixture.VarHandlePolymorphic"));
    final boolean retained =
        analysis
            .retainedClasses()
            .containsAll(Set.of("fixture/VarHandlePolymorphic", DESCRIPTOR_ONLY));
    final Path retainedJar =
        SignaturePolymorphicTestSupport.writeRetainedJar(
            temporaryDirectory, candidateJar, analysis.retainedClasses());
    try (URLClassLoader loader =
        new URLClassLoader(
            new java.net.URL[] {retainedJar.toUri().toURL()},
            ClassLoader.getPlatformClassLoader())) {
      final Object value =
          loader.loadClass("fixture.VarHandlePolymorphic").getMethod("run").invoke(null);
      assertThat(List.of(retained, "fixture.DescriptorOnly".equals(value.getClass().getName())))
          .containsExactly(true, true);
    }
  }
}
