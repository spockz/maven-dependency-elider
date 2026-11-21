/* WHY: Shares one platform snapshot and bytecode fixtures across closed-world policy tests. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;

/** WHY: These builders share one class-file vocabulary across closure tests. */
@SuppressWarnings("PMD.TooManyMethods")
public final class ClosedWorldTestFixtures {
  /** Candidate root class in bytecode form. */
  public static final String ROOT = "fixture/Root";

  /** Candidate root class in analysis-root form. */
  public static final String ROOT_NAME = "fixture.Root";

  /** Static-linkage fixture superclass. */
  public static final String BASE = "fixture/Base";

  /** Admitted method-body fixture dependency. */
  public static final String BODY = "fixture/Body";

  /** Sibling library root fixture. */
  public static final String LIBRARY_ROOT = "fixture/LibraryRoot";

  /** Excluded body-only target used in closure queries. */
  public static final String MISSING_BODY = "fixture/MissingBody";

  /** Unresolved target shared by structural and body edges. */
  public static final String MISSING = "fixture/Missing";

  /** Standard platform class used to prove pool fallback resolution. */
  public static final String OBJECT = "java/lang/Object";

  /** Interface metadata fixture. */
  public static final String MARKER = "fixture/Marker";

  /** Method exception metadata fixture. */
  public static final String DECLARED_EXCEPTION = "fixture/DeclaredException";

  /** Catch type metadata fixture. */
  public static final String CATCH_TYPE = "fixture/CatchType";

  /** Record component annotation value fixture. */
  public static final String RECORD_ONLY_TYPE = "fixture/RecordOnlyType";

  /** Shared platform classes avoid repeated JDK scans across the nested suites. */
  private static final ClassPool JDK_CLASS_TABLE = readRuntimeApi();

  /** WHY: Fixture methods all use one invocation name for bytecode targets. */
  private static final String CALL_METHOD_NAME = "call";

  /** WHY: Fixture methods use the same empty void method descriptor. */
  private static final String NO_ARGUMENT_VOID_DESCRIPTOR = "()V";

  /** Prevents fixture utility construction. */
  private ClosedWorldTestFixtures() {}

  /** Prepares a candidate without sibling archives. */
  public static DependencyJarTrimmer.PreparedAnalysis prepare(final Path candidate)
      throws IOException {
    return prepare(candidate, java.util.List.of());
  }

  /** Prepares a candidate with ordered sibling archives. */
  public static DependencyJarTrimmer.PreparedAnalysis prepare(
      final Path candidate, final java.util.List<Path> libraries) throws IOException {
    return new DependencyJarTrimmer()
        .prepareInternal(
            candidate, libraries, JDK_CLASS_TABLE, false, Set.of(), ArchiveSnapshot::read);
  }

  /** Writes one fixture archive. */
  // WHY: Each archive member needs a fresh JarEntry.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  public static Path writeJar(
      final Path directory, final String name, final Map<String, byte[]> classes)
      throws IOException {
    final Path archive = directory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(archive))) {
      for (final Map.Entry<String, byte[]> entry : classes.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey() + ".class"));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return archive;
  }

  /** Emits one minimal class with a static call target. */
  public static byte[] simpleClass(final String name) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, OBJECT, null);
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            CALL_METHOD_NAME,
            NO_ARGUMENT_VOID_DESCRIPTOR,
            null,
            null);
    method.visitCode();
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Emits a stack-map frame naming a class absent from instructions. */
  public static byte[] classWithFrameReference(final String name, final String frameType) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, OBJECT, null);
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "run",
            NO_ARGUMENT_VOID_DESCRIPTOR,
            null,
            null);
    final org.objectweb.asm.Label framed = new org.objectweb.asm.Label();
    method.visitCode();
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitLabel(framed);
    method.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[] {frameType});
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Emits local-variable metadata naming a class absent from operations. */
  public static byte[] classWithLocalVariableType(final String name, final String localType) {
    return classWithLocalVariableMetadata(name, "L" + localType + ";", null, null);
  }

  /** Emits local-variable debug descriptors and generic signatures. */
  public static byte[] classWithLocalVariableMetadata(
      final String name, final String descriptor, final String signature) {
    return classWithLocalVariableMetadata(name, descriptor, signature, null);
  }

  private static byte[] classWithLocalVariableMetadata(
      final String name, final String descriptor, final String signature, final String fieldType) {
    return classWithLocalVariableMetadata(name, descriptor, signature, fieldType, null);
  }

  private static byte[] classWithLocalVariableMetadata(
      final String name,
      final String descriptor,
      final String signature,
      final String fieldType,
      final String bodyType) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, OBJECT, null);
    if (fieldType != null) {
      writer
          .visitField(Opcodes.ACC_PUBLIC, "reference", "L" + fieldType + ";", null, null)
          .visitEnd();
    }
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "run",
            NO_ARGUMENT_VOID_DESCRIPTOR,
            null,
            null);
    final org.objectweb.asm.Label start = new org.objectweb.asm.Label();
    final org.objectweb.asm.Label end = new org.objectweb.asm.Label();
    method.visitCode();
    method.visitLabel(start);
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitVarInsn(Opcodes.ASTORE, 0);
    method.visitVarInsn(Opcodes.ALOAD, 0);
    method.visitInsn(Opcodes.POP);
    if (bodyType != null) {
      method.visitMethodInsn(
          Opcodes.INVOKESTATIC, bodyType, CALL_METHOD_NAME, NO_ARGUMENT_VOID_DESCRIPTOR, false);
    }
    method.visitLabel(end);
    method.visitInsn(Opcodes.RETURN);
    method.visitLocalVariable("unused", descriptor, signature, start, end, 0);
    method.visitMaxs(1, 1);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Emits field linkage and local-variable debug metadata in one class. */
  public static byte[] classWithFieldAndLocalVariableType(final String name, final String type) {
    return classWithLocalVariableMetadata(name, "L" + type + ";", null, type);
  }

  /** Emits a body call and local-variable debug metadata to the same class. */
  public static byte[] classWithLocalVariableTypeAndBodyCall(
      final String name, final String localType, final String bodyType) {
    return classWithLocalVariableMetadata(name, "L" + localType + ";", null, null, bodyType);
  }

  /** Emits a class with an attribute the reference visitor cannot interpret. */
  public static byte[] classWithUnknownAttribute(final String name, final String attributeName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, OBJECT, null);
    writer.visitAttribute(
        new Attribute(attributeName) {
          @Override
          protected ByteVector write(
              final ClassWriter classWriter,
              final byte[] code,
              final int codeLength,
              final int maxStack,
              final int maxLocals) {
            return new ByteVector();
          }
        });
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Emits one class with a structural field descriptor. */
  public static byte[] classWithField(final String name, final String fieldType) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, OBJECT, null);
    writer
        .visitField(Opcodes.ACC_PUBLIC, "reference", "L" + fieldType + ";", null, null)
        .visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Emits an annotated method whose body invokes another class. */
  public static byte[] classWithAnnotatedMethodAndBodyCall(
      final String name, final String annotationType, final String bodyType) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, OBJECT, null);
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "run",
            NO_ARGUMENT_VOID_DESCRIPTOR,
            null,
            null);
    method.visitAnnotation("L" + annotationType + ";", true).visitEnd();
    method.visitCode();
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC, bodyType, CALL_METHOD_NAME, NO_ARGUMENT_VOID_DESCRIPTOR, false);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Emits a field with a separately encoded generic signature. */
  public static byte[] classWithGenericField(
      final String name, final String descriptor, final String signature) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, OBJECT, null);
    writer.visitField(Opcodes.ACC_PUBLIC, "reference", descriptor, signature, null).visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Emits an intentionally malformed field descriptor. */
  public static byte[] malformedDescriptorClass() {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, ROOT, null, OBJECT, null);
    writer.visitField(Opcodes.ACC_PUBLIC, "broken", "Lfixture/Unclosed", null, null).visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Emits structural superclass plus method-body calls. */
  public static byte[] classWithSuperclassAndCalls(
      final String name, final String superclass, final String... targets) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, superclass, null);
    if (targets.length > 0) {
      final MethodVisitor method =
          writer.visitMethod(Opcodes.ACC_PUBLIC, "invoke", NO_ARGUMENT_VOID_DESCRIPTOR, null, null);
      method.visitCode();
      for (final String target : targets) {
        method.visitMethodInsn(
            Opcodes.INVOKESTATIC, target, CALL_METHOD_NAME, NO_ARGUMENT_VOID_DESCRIPTOR, false);
      }
      method.visitInsn(Opcodes.RETURN);
      method.visitMaxs(0, 0);
      method.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Builds record/signature fixtures kept together for structural closure tests. */
  public static final class Structural {
    private Structural() {}

    /** Builds all candidate classes referenced by the structural root fixture. */
    public static Map<String, byte[]> fixtureClasses() {
      return Map.ofEntries(
          Map.entry(ROOT, rootClass()),
          Map.entry(MARKER, simpleClass(MARKER)),
          Map.entry("fixture/FieldType", simpleClass("fixture/FieldType")),
          Map.entry("fixture/Outer", simpleClass("fixture/Outer")),
          Map.entry("fixture/Outer$Inner", simpleClass("fixture/Outer$Inner")),
          Map.entry("fixture/GenericArgument", simpleClass("fixture/GenericArgument")),
          Map.entry("fixture/Parameter", simpleClass("fixture/Parameter")),
          Map.entry("fixture/Return", simpleClass("fixture/Return")),
          Map.entry(DECLARED_EXCEPTION, simpleClass(DECLARED_EXCEPTION)),
          Map.entry(CATCH_TYPE, simpleClass(CATCH_TYPE)),
          Map.entry("fixture/ComponentType", simpleClass("fixture/ComponentType")),
          Map.entry("fixture/RecordOnly", simpleClass("fixture/RecordOnly")),
          Map.entry(RECORD_ONLY_TYPE, simpleClass(RECORD_ONLY_TYPE)));
    }

    /** Lists classes required by structural closure from the root fixture. */
    public static Set<String> targets() {
      return Set.of(
          MARKER,
          "fixture/FieldType",
          "fixture/Outer",
          "fixture/Outer$Inner",
          "fixture/GenericArgument",
          "fixture/Parameter",
          "fixture/Return",
          DECLARED_EXCEPTION,
          CATCH_TYPE,
          "fixture/ComponentType",
          "fixture/RecordOnly",
          RECORD_ONLY_TYPE);
    }

    /** Emits hierarchy, signature, descriptor, exception, and record metadata edges. */
    public static byte[] rootClass() {
      final ClassWriter writer = new ClassWriter(0);
      writer.visit(
          Opcodes.V21,
          Opcodes.ACC_PUBLIC | Opcodes.ACC_RECORD,
          ROOT,
          "Ljava/lang/Record;Lfixture/Marker;",
          "java/lang/Record",
          new String[] {MARKER});
      writer.visitField(Opcodes.ACC_PUBLIC, "field", "Lfixture/FieldType;", null, null).visitEnd();
      writer
          .visitField(
              Opcodes.ACC_PUBLIC,
              "nested",
              "Ljava/lang/Object;",
              "Lfixture/Outer<Lfixture/GenericArgument;>.Inner;",
              null)
          .visitEnd();
      final MethodVisitor method =
          writer.visitMethod(
              Opcodes.ACC_PUBLIC,
              "lookup",
              "(Lfixture/Parameter;)Lfixture/Return;",
              null,
              new String[] {DECLARED_EXCEPTION});
      final org.objectweb.asm.Label start = new org.objectweb.asm.Label();
      final org.objectweb.asm.Label end = new org.objectweb.asm.Label();
      final org.objectweb.asm.Label handler = new org.objectweb.asm.Label();
      method.visitTryCatchBlock(start, end, handler, CATCH_TYPE);
      method.visitCode();
      method.visitLabel(start);
      method.visitInsn(Opcodes.ACONST_NULL);
      method.visitInsn(Opcodes.ARETURN);
      method.visitLabel(end);
      method.visitLabel(handler);
      method.visitInsn(Opcodes.ATHROW);
      method.visitMaxs(1, 2);
      method.visitEnd();
      final org.objectweb.asm.RecordComponentVisitor component =
          writer.visitRecordComponent("component", "Lfixture/ComponentType;", null);
      final org.objectweb.asm.AnnotationVisitor annotation =
          component.visitAnnotation("Lfixture/RecordOnly;", true);
      annotation.visit("value", org.objectweb.asm.Type.getObjectType(RECORD_ONLY_TYPE));
      annotation.visitEnd();
      component.visitEnd();
      writer.visitEnd();
      return writer.toByteArray();
    }
  }

  private static ClassPool readRuntimeApi() {
    try {
      return new JdkApiClassTableReader().readFrozen();
    } catch (final IOException exception) {
      throw new ExceptionInInitializerError(exception);
    }
  }
}
