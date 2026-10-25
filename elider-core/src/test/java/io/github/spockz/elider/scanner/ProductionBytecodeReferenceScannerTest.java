/* WHY: Proves bytecode references are an independent complete evidence source and that an empty
 * result is distinguishable from unavailable production output. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Covers production bytecode scanning semantics. */
@SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
class ProductionBytecodeReferenceScannerTest {
  /** Descriptor shared by generated no argument void methods. */
  private static final String NO_ARGUMENT_VOID_METHOD = "()V";

  /** Name shared by generated annotation and record values. */
  private static final String VALUE_NAME = "value";

  /** PMD rule locally waived for semantic tests with multiple related claims. */
  private static final String MULTI_ASSERT_RULE = "PMD.UnitTestContainsTooManyAsserts";

  /** Supplies isolated production class output directories. */
  @TempDir Path tempDir;

  /** Creates package-visible test instance for JUnit. */
  ProductionBytecodeReferenceScannerTest() {}

  @Test
  @SuppressWarnings(MULTI_ASSERT_RULE)
  void collectsDirectSymbolicReferencesButIgnoresClassNameStrings() throws IOException {
    final Path output = Files.createDirectory(tempDir.resolve("classes"));
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/App", null, "sample/Base", null);
    writer.visitField(Opcodes.ACC_PRIVATE, "field", "Lsample/FieldType;", null, null).visitEnd();
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "call", NO_ARGUMENT_VOID_METHOD, null, null);
    method.visitCode();
    method.visitLdcInsn("sample/OnlyAString");
    method.visitInsn(Opcodes.POP);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC, "sample/Called", "run", NO_ARGUMENT_VOID_METHOD, false);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    Files.write(output.resolve("App.class"), writer.toByteArray());

    final BytecodeReferenceScan result = new ProductionBytecodeReferenceScanner().scan(output);

    assertThat(result.referencedClasses())
        .contains("sample.Base", "sample.FieldType", "sample.Called")
        .doesNotContain("sample.OnlyAString");
    assertThat(result.classFilesScanned()).isEqualTo(1);
    assertThat(result.complete()).isTrue();
    assertThat(result.scope()).isEqualTo(output.toAbsolutePath().normalize());
  }

  @Test
  void collectsNestedGenericSignaturesAndAnnotationTypeValues() throws IOException {
    final Path output = Files.createDirectory(tempDir.resolve("signature-classes"));
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC,
        "sample/SignatureApp",
        "<T:Ljava/lang/Object;>Ljava/lang/Object;Lsample/Outer<Ljava/lang/String;>"
            + ".Inner<Lsample/Arg;>;",
        "java/lang/Object",
        null);
    final org.objectweb.asm.AnnotationVisitor annotation =
        writer.visitAnnotation("Lsample/TypeAnnotation;", true);
    annotation.visit(VALUE_NAME, Type.getObjectType("sample/AnnotationValue"));
    annotation.visitEnum("kind", "Lsample/AnnotationEnum;", "VALUE");
    final org.objectweb.asm.AnnotationVisitor array = annotation.visitArray("values");
    array.visit(null, Type.getObjectType("sample/ArrayAnnotationValue"));
    array.visitEnd();
    annotation.visitEnd();
    writer.visitEnd();
    Files.write(output.resolve("SignatureApp.class"), writer.toByteArray());

    final BytecodeReferenceScan result = new ProductionBytecodeReferenceScanner().scan(output);

    assertThat(result.referencedClasses())
        .contains(
            "sample.Outer",
            "sample.Outer$Inner",
            "java.lang.String",
            "sample.Arg",
            "sample.TypeAnnotation",
            "sample.AnnotationValue",
            "sample.AnnotationEnum",
            "sample.ArrayAnnotationValue");
  }

  @Test
  void collectsAnnotationDefaultRecordTypeAndCodeAnnotationTypes() throws IOException {
    final Path output = Files.createDirectory(tempDir.resolve("annotation-classes"));
    final ClassWriter annotationWriter = new ClassWriter(0);
    annotationWriter.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT | Opcodes.ACC_ANNOTATION,
        "sample/AnnotationType",
        null,
        "java/lang/Object",
        new String[] {"java/lang/annotation/Annotation"});
    final MethodVisitor annotationMethod =
        annotationWriter.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
            VALUE_NAME,
            "()Ljava/lang/Class;",
            null,
            null);
    annotationMethod
        .visitAnnotationDefault()
        .visit(null, Type.getObjectType("sample/DefaultValue"));
    annotationWriter.visitEnd();
    Files.write(output.resolve("AnnotationType.class"), annotationWriter.toByteArray());

    final ClassWriter recordWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    recordWriter.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_RECORD,
        "sample/Record",
        null,
        "java/lang/Record",
        null);
    recordWriter
        .visitRecordComponent(VALUE_NAME, "Ljava/lang/String;", null)
        .visitTypeAnnotation(
            org.objectweb.asm.TypeReference.newTypeReference(org.objectweb.asm.TypeReference.FIELD)
                .getValue(),
            null,
            "Lsample/RecordTypeAnnotation;",
            true)
        .visitEnd();
    final MethodVisitor method =
        recordWriter.visitMethod(Opcodes.ACC_PUBLIC, "run", "(Ljava/lang/Object;)V", null, null);
    method.visitParameterAnnotation(0, "Lsample/ParameterAnnotation;", true).visitEnd();
    final Label start = new Label();
    final Label end = new Label();
    final Label handler = new Label();
    method.visitCode();
    method.visitTryCatchBlock(start, end, handler, "java/lang/Exception");
    method
        .visitTryCatchAnnotation(
            org.objectweb.asm.TypeReference.newTryCatchReference(0).getValue(),
            null,
            "Lsample/TryCatchAnnotation;",
            true)
        .visitEnd();
    method.visitLabel(start);
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitTypeInsn(Opcodes.INSTANCEOF, "sample/CheckedType");
    method
        .visitInsnAnnotation(
            org.objectweb.asm.TypeReference.newTypeReference(
                    org.objectweb.asm.TypeReference.INSTANCEOF)
                .getValue(),
            null,
            "Lsample/InstructionAnnotation;",
            true)
        .visitEnd();
    method.visitInsn(Opcodes.POP);
    method.visitLabel(end);
    method.visitInsn(Opcodes.RETURN);
    method.visitLabel(handler);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method
        .visitLocalVariableAnnotation(
            org.objectweb.asm.TypeReference.newTypeReference(
                    org.objectweb.asm.TypeReference.LOCAL_VARIABLE)
                .getValue(),
            null,
            new Label[] {start},
            new Label[] {end},
            new int[] {0},
            "Lsample/LocalVariableAnnotation;",
            true)
        .visitEnd();
    method.visitMaxs(0, 0);
    method.visitEnd();
    recordWriter.visitEnd();
    Files.write(output.resolve("Record.class"), recordWriter.toByteArray());

    final BytecodeReferenceScan result = new ProductionBytecodeReferenceScanner().scan(output);

    assertThat(result.referencedClasses())
        .contains(
            "sample.DefaultValue",
            "sample.RecordTypeAnnotation",
            "sample.ParameterAnnotation",
            "sample.TryCatchAnnotation",
            "sample.CheckedType",
            "sample.InstructionAnnotation",
            "sample.LocalVariableAnnotation");
  }

  @Test
  void collectsInvokeDynamicHandlesNestedConstantDynamicAndArrayTypes() throws IOException {
    final Path output = Files.createDirectory(tempDir.resolve("bootstrap-classes"));
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/BootstrapApp", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "run", NO_ARGUMENT_VOID_METHOD, null, null);
    method.visitCode();
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitTypeInsn(Opcodes.CHECKCAST, "[Lsample/ArrayCast;");
    method.visitInsn(Opcodes.POP);
    method.visitFrame(Opcodes.F_APPEND, 1, new Object[] {"[Lsample/FrameArray;"}, 0, null);
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitMethodInsn(
        Opcodes.INVOKEVIRTUAL, "[Lsample/ArrayOwner;", "clone", "()Ljava/lang/Object;", false);
    method.visitInsn(Opcodes.POP);
    final Handle bootstrap =
        new Handle(
            Opcodes.H_INVOKESTATIC, "sample/Bootstrap", "link", "()Ljava/lang/Object;", false);
    final Handle target =
        new Handle(Opcodes.H_INVOKESTATIC, "sample/Target", "call", "(Lsample/Argument;)V", false);
    final ConstantDynamic nested =
        new ConstantDynamic(
            "nested", "Lsample/NestedValue;", bootstrap, Type.getObjectType("sample/CondensedArg"));
    final ConstantDynamic constant =
        new ConstantDynamic(VALUE_NAME, "Lsample/ConstantValue;", bootstrap, target, nested);
    method.visitInvokeDynamicInsn("call", NO_ARGUMENT_VOID_METHOD, bootstrap, target, constant);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    Files.write(output.resolve("BootstrapApp.class"), writer.toByteArray());

    final BytecodeReferenceScan result = new ProductionBytecodeReferenceScanner().scan(output);

    assertThat(result.referencedClasses())
        .contains(
            "sample.ArrayCast",
            "sample.FrameArray",
            "sample.ArrayOwner",
            "sample.Bootstrap",
            "sample.Target",
            "sample.Argument",
            "sample.NestedValue",
            "sample.CondensedArg",
            "sample.ConstantValue");
  }

  @Test
  void collectsModuleMainServiceAndProviderReferences() throws IOException {
    final Path output = Files.createDirectory(tempDir.resolve("module-classes"));
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_MODULE, "module-info", null, null, null);
    final org.objectweb.asm.ModuleVisitor module = writer.visitModule("sample.module", 0, null);
    module.visitMainClass("sample/Main");
    module.visitUse("sample/Service");
    module.visitProvide("sample/Service", "sample/Provider");
    writer.visitEnd();
    Files.write(output.resolve("module-info.class"), writer.toByteArray());

    final BytecodeReferenceScan result = new ProductionBytecodeReferenceScanner().scan(output);

    assertThat(result.referencedClasses())
        .contains("sample.Main", "sample.Service", "sample.Provider");
  }

  @Test
  @SuppressWarnings(MULTI_ASSERT_RULE)
  void distinguishesCompleteEmptyScanFromMissingOutput() throws IOException {
    final Path output = Files.createDirectory(tempDir.resolve("empty-classes"));

    final BytecodeReferenceScan result = new ProductionBytecodeReferenceScanner().scan(output);

    assertThat(result.referencedClasses()).isEmpty();
    assertThat(result.classFilesScanned()).isZero();
    assertThat(result.complete()).isTrue();
    assertThatIOException()
        .isThrownBy(
            () -> new ProductionBytecodeReferenceScanner().scan(tempDir.resolve("missing")));
  }

  @Test
  @SuppressWarnings(MULTI_ASSERT_RULE)
  void resultNormalizesNamesToSortedImmutableDottedNames() {
    final BytecodeReferenceScan result =
        new BytecodeReferenceScan(
            tempDir, new LinkedHashSet<>(java.util.List.of("z/Z", "a.A")), 0, true);

    assertThat(result.referencedClasses()).containsExactly("a.A", "z.Z");
    assertThat(result.referencedClasses()).isUnmodifiable();
  }

  @Test
  @SuppressWarnings(MULTI_ASSERT_RULE)
  void rejectsMalformedClassFilesAndSymbolicLinks() throws IOException {
    final Path malformed = Files.createDirectory(tempDir.resolve("malformed-classes"));
    Files.writeString(malformed.resolve("Broken.class"), "not a class file");
    assertThatIOException()
        .isThrownBy(() -> new ProductionBytecodeReferenceScanner().scan(malformed));

    final Path linked = Files.createDirectory(tempDir.resolve("linked-classes"));
    final Path outside = Files.writeString(tempDir.resolve("outside.class"), "not followed");
    Files.createSymbolicLink(linked.resolve("Linked.class"), outside);
    assertThatIOException().isThrownBy(() -> new ProductionBytecodeReferenceScanner().scan(linked));
  }
}
