/* WHY: Shares ASM9 class, metadata, signature, and method-body reference traversal across scanners
 * and graph builders. */

package io.github.spockz.elider.scanner;

import java.util.Objects;
import java.util.function.BiConsumer;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.RecordComponentVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.TypePath;
import org.objectweb.asm.signature.SignatureReader;
import org.objectweb.asm.signature.SignatureVisitor;

/** Collects symbolic internal-name references from ASM class-file callbacks. */
@SuppressWarnings({"PMD.GodClass", "PMD.TooManyMethods"})
public final class AsmClassReferenceVisitor extends ClassVisitor {
  /** Classifies where a symbolic reference appeared in the class file. */
  public enum ReferenceKind {
    /** Class, field, method, record component, annotation, or try-catch metadata. */
    STRUCTURAL,
    /** Method-body bytecode instructions and invokedynamic/constant pool operands. */
    BODY,
    /** Local-variable debug metadata. */
    DEBUG_METADATA
  }

  /** Opening delimiter for method descriptors. */
  private static final char METHOD_DESCRIPTOR_START = '(';

  /** Closing delimiter for method descriptors. */
  private static final char METHOD_DESCRIPTOR_END = ')';

  /** Prefix for internal-name object descriptors. */
  private static final char OBJECT_DESCRIPTOR_PREFIX = 'L';

  /** Descriptor character for void return types. */
  private static final char VOID_DESCRIPTOR = 'V';

  /** Source class identity for diagnostics. */
  private final String sourceClass;

  /** Whether method-body instructions are recorded. */
  private final boolean includeMethodBodies;

  /** Sink receiving internal class names and edge kinds. */
  private final BiConsumer<String, ReferenceKind> consumer;

  /** Reusable stateless method visitor. */
  private final MethodVisitor methodVisitor = new MethodReferenceVisitor();

  /** Reusable stateless field visitor. */
  private final FieldVisitor fieldVisitor = createFieldVisitor();

  /** Reusable stateless record-component visitor. */
  private final RecordComponentVisitor recordComponentVisitor = createRecordComponentVisitor();

  /** Reusable stateless module visitor. */
  private final ModuleVisitor moduleVisitor = createModuleVisitor();

  /** Reusable stateless annotation visitor for structural metadata. */
  private final AnnotationVisitor structuralAnnotationVisitor =
      createAnnotationVisitor(ReferenceKind.STRUCTURAL);

  /** Reusable stateless annotation visitor for method-body constants. */
  private final AnnotationVisitor bodyAnnotationVisitor =
      createAnnotationVisitor(ReferenceKind.BODY);

  /** Reusable stateless annotation visitor for debug metadata. */
  private final AnnotationVisitor debugAnnotationVisitor =
      createAnnotationVisitor(ReferenceKind.DEBUG_METADATA);

  /** Creates a visitor for internal class names. */
  public AsmClassReferenceVisitor(
      final String sourceClass,
      final boolean includeMethodBodies,
      final BiConsumer<String, ReferenceKind> consumer) {
    super(Opcodes.ASM9);
    this.sourceClass = Objects.requireNonNull(sourceClass, "sourceClass");
    this.includeMethodBodies = includeMethodBodies;
    this.consumer = Objects.requireNonNull(consumer, "consumer");
  }

  @Override
  public void visit(
      final int version,
      final int access,
      final String name,
      final String signature,
      final String superName,
      final String[] interfaces) {
    addInternalName(superName, ReferenceKind.STRUCTURAL);
    if (interfaces != null) {
      for (final String interfaceName : interfaces) {
        addInternalName(interfaceName, ReferenceKind.STRUCTURAL);
      }
    }
    addSignature(signature, ReferenceKind.STRUCTURAL);
  }

  @Override
  public ModuleVisitor visitModule(final String name, final int access, final String version) {
    return moduleVisitor;
  }

  private ModuleVisitor createModuleVisitor() {
    return new ModuleVisitor(Opcodes.ASM9) {
      @Override
      public void visitMainClass(final String mainClass) {
        addInternalName(mainClass, ReferenceKind.STRUCTURAL);
      }

      @Override
      public void visitUse(final String service) {
        addInternalName(service, ReferenceKind.STRUCTURAL);
      }

      @Override
      public void visitProvide(final String service, final String... providers) {
        addInternalName(service, ReferenceKind.STRUCTURAL);
        if (providers != null) {
          for (final String provider : providers) {
            addInternalName(provider, ReferenceKind.STRUCTURAL);
          }
        }
      }
    };
  }

  @Override
  public void visitOuterClass(final String owner, final String name, final String descriptor) {
    addInternalName(owner, ReferenceKind.STRUCTURAL);
    addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
  }

  @Override
  public void visitNestHost(final String nestHost) {
    addInternalName(nestHost, ReferenceKind.STRUCTURAL);
  }

  @Override
  public void visitNestMember(final String nestMember) {
    addInternalName(nestMember, ReferenceKind.STRUCTURAL);
  }

  @Override
  public void visitPermittedSubclass(final String permittedSubclass) {
    addInternalName(permittedSubclass, ReferenceKind.STRUCTURAL);
  }

  @Override
  public void visitInnerClass(
      final String name, final String outerName, final String innerName, final int access) {
    addInternalName(name, ReferenceKind.STRUCTURAL);
    addInternalName(outerName, ReferenceKind.STRUCTURAL);
  }

  @Override
  public AnnotationVisitor visitAnnotation(final String descriptor, final boolean visible) {
    addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
    return annotationVisitor(ReferenceKind.STRUCTURAL);
  }

  @Override
  public AnnotationVisitor visitTypeAnnotation(
      final int typeRef, final TypePath typePath, final String descriptor, final boolean visible) {
    addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
    return annotationVisitor(ReferenceKind.STRUCTURAL);
  }

  @Override
  public FieldVisitor visitField(
      final int access,
      final String name,
      final String descriptor,
      final String signature,
      final Object value) {
    addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
    addSignature(signature, ReferenceKind.STRUCTURAL);
    return fieldVisitor;
  }

  private FieldVisitor createFieldVisitor() {
    return new FieldVisitor(Opcodes.ASM9) {
      @Override
      public AnnotationVisitor visitAnnotation(
          final String annotationDescriptor, final boolean visible) {
        addDescriptor(annotationDescriptor, ReferenceKind.STRUCTURAL);
        return annotationVisitor(ReferenceKind.STRUCTURAL);
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(
          final int typeRef,
          final TypePath typePath,
          final String annotationDescriptor,
          final boolean visible) {
        addDescriptor(annotationDescriptor, ReferenceKind.STRUCTURAL);
        return annotationVisitor(ReferenceKind.STRUCTURAL);
      }
    };
  }

  @Override
  public RecordComponentVisitor visitRecordComponent(
      final String name, final String descriptor, final String signature) {
    addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
    addSignature(signature, ReferenceKind.STRUCTURAL);
    return recordComponentVisitor;
  }

  private RecordComponentVisitor createRecordComponentVisitor() {
    return new RecordComponentVisitor(Opcodes.ASM9) {
      @Override
      public AnnotationVisitor visitAnnotation(
          final String annotationDescriptor, final boolean visible) {
        addDescriptor(annotationDescriptor, ReferenceKind.STRUCTURAL);
        return annotationVisitor(ReferenceKind.STRUCTURAL);
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(
          final int typeRef,
          final TypePath typePath,
          final String annotationDescriptor,
          final boolean visible) {
        addDescriptor(annotationDescriptor, ReferenceKind.STRUCTURAL);
        return annotationVisitor(ReferenceKind.STRUCTURAL);
      }
    };
  }

  @Override
  public MethodVisitor visitMethod(
      final int access,
      final String name,
      final String descriptor,
      final String signature,
      final String[] exceptions) {
    addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
    addSignature(signature, ReferenceKind.STRUCTURAL);
    if (exceptions != null) {
      for (final String exception : exceptions) {
        addInternalName(exception, ReferenceKind.STRUCTURAL);
      }
    }
    return methodVisitor;
  }

  private AnnotationVisitor annotationVisitor(final ReferenceKind kind) {
    return switch (kind) {
      case STRUCTURAL -> structuralAnnotationVisitor;
      case BODY -> bodyAnnotationVisitor;
      case DEBUG_METADATA -> debugAnnotationVisitor;
    };
  }

  private AnnotationVisitor createAnnotationVisitor(final ReferenceKind kind) {
    return new AnnotationVisitor(Opcodes.ASM9) {
      @Override
      public void visit(final String name, final Object value) {
        if (value instanceof Type type) {
          addType(type, kind);
        }
      }

      @Override
      public void visitEnum(final String name, final String descriptor, final String value) {
        addDescriptor(descriptor, kind);
      }

      @Override
      public AnnotationVisitor visitAnnotation(final String name, final String descriptor) {
        addDescriptor(descriptor, kind);
        return annotationVisitor(kind);
      }

      @Override
      public AnnotationVisitor visitArray(final String name) {
        return annotationVisitor(kind);
      }
    };
  }

  // WHY: SignatureReader uses varied unchecked failures for malformed forms.
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private void addSignature(final String signature, final ReferenceKind kind) {
    if (signature == null) {
      return;
    }
    try {
      new SignatureReader(signature).accept(signatureVisitor(kind));
    } catch (final RuntimeException exception) {
      throw new IllegalArgumentException(
          "Invalid reference signature in " + sourceClass + ": " + signature, exception);
    }
  }

  private SignatureVisitor signatureVisitor(final ReferenceKind kind) {
    return new SignatureVisitor(Opcodes.ASM9) {
      /** Enclosing class within this signature scope. */
      private String currentClassType;

      @Override
      public void visitClassType(final String name) {
        currentClassType = name;
        addInternalName(name, kind);
      }

      @Override
      public void visitInnerClassType(final String name) {
        currentClassType = currentClassType + "$" + name;
        addInternalName(currentClassType, kind);
      }

      @Override
      public SignatureVisitor visitClassBound() {
        return signatureVisitor(kind);
      }

      @Override
      public SignatureVisitor visitInterfaceBound() {
        return signatureVisitor(kind);
      }

      @Override
      public SignatureVisitor visitSuperclass() {
        return signatureVisitor(kind);
      }

      @Override
      public SignatureVisitor visitInterface() {
        return signatureVisitor(kind);
      }

      @Override
      public SignatureVisitor visitParameterType() {
        return signatureVisitor(kind);
      }

      @Override
      public SignatureVisitor visitReturnType() {
        return signatureVisitor(kind);
      }

      @Override
      public SignatureVisitor visitExceptionType() {
        return signatureVisitor(kind);
      }

      @Override
      public SignatureVisitor visitArrayType() {
        return signatureVisitor(kind);
      }

      @Override
      public SignatureVisitor visitTypeArgument(final char wildcard) {
        return signatureVisitor(kind);
      }
    };
  }

  private void addDescriptor(final String descriptor, final ReferenceKind kind) {
    if (descriptor == null) {
      return;
    }
    final int length = descriptor.length();
    if (length == 0) {
      throw invalidDescriptor(descriptor);
    }
    final int end =
        descriptor.charAt(0) == METHOD_DESCRIPTOR_START
            ? parseMethodDescriptor(descriptor, length, kind)
            : parseTypeDescriptor(descriptor, 0, length, kind, true);
    if (end != length) {
      throw invalidDescriptor(descriptor);
    }
  }

  private int parseMethodDescriptor(
      final String descriptor, final int length, final ReferenceKind kind) {
    int pos = 1;
    while (pos < length && descriptor.charAt(pos) != METHOD_DESCRIPTOR_END) {
      pos = parseTypeDescriptor(descriptor, pos, length, kind, false);
      if (pos < 0) {
        return -1;
      }
    }
    if (pos >= length || descriptor.charAt(pos) != METHOD_DESCRIPTOR_END) {
      return -1;
    }
    return parseTypeDescriptor(descriptor, pos + 1, length, kind, true);
  }

  private IllegalArgumentException invalidDescriptor(final String descriptor) {
    return new IllegalArgumentException(
        "Invalid reference descriptor in " + sourceClass + ": " + descriptor);
  }

  private int parseTypeDescriptor(
      final String descriptor,
      final int start,
      final int length,
      final ReferenceKind kind,
      final boolean allowVoid) {
    int pos = start;
    boolean voidAllowed = allowVoid;
    while (pos < length && descriptor.charAt(pos) == '[') {
      pos++;
      voidAllowed = false;
    }
    if (pos >= length) {
      return -1;
    }
    return parseElementDescriptor(descriptor, pos, kind, voidAllowed);
  }

  private int parseElementDescriptor(
      final String descriptor, final int pos, final ReferenceKind kind, final boolean voidAllowed) {
    final char tag = descriptor.charAt(pos);
    if (tag == OBJECT_DESCRIPTOR_PREFIX) {
      return parseObjectDescriptor(descriptor, pos, kind);
    }
    if (tag == VOID_DESCRIPTOR) {
      return voidAllowed ? pos + 1 : -1;
    }
    return isPrimitiveTag(tag) ? pos + 1 : -1;
  }

  private static boolean isPrimitiveTag(final char tag) {
    return tag == 'B'
        || tag == 'C'
        || tag == 'D'
        || tag == 'F'
        || tag == 'I'
        || tag == 'J'
        || tag == 'S'
        || tag == 'Z';
  }

  private int parseObjectDescriptor(
      final String descriptor, final int start, final ReferenceKind kind) {
    final int end = descriptor.indexOf(';', start + 1);
    if (end <= start + 1) {
      return -1;
    }
    addInternalName(descriptor.substring(start + 1, end), kind);
    return end + 1;
  }

  private void addType(final Type type, final ReferenceKind kind) {
    switch (type.getSort()) {
      case Type.METHOD -> {
        addType(type.getReturnType(), kind);
        for (final Type argument : type.getArgumentTypes()) {
          addType(argument, kind);
        }
      }
      case Type.ARRAY -> addType(type.getElementType(), kind);
      case Type.OBJECT -> addInternalName(type.getInternalName(), kind);
      default -> {}
    }
  }

  private void addInternalName(final String name, final ReferenceKind kind) {
    if (name == null || name.isEmpty()) {
      return;
    }
    if (name.startsWith("[")) {
      addDescriptor(name, kind);
      return;
    }
    consumer.accept(name, kind);
  }

  private void addHandle(final Handle handle) {
    addInternalName(handle.getOwner(), ReferenceKind.BODY);
    addDescriptor(handle.getDesc(), ReferenceKind.BODY);
  }

  private void addFrameTypes(final Object[] types, final int count) {
    if (types == null) {
      return;
    }
    for (int index = 0; index < count; index++) {
      if (types[index] instanceof String name) {
        addInternalName(name, ReferenceKind.STRUCTURAL);
      }
    }
  }

  private void addConstant(final Object value) {
    switch (value) {
      case Type type -> addType(type, ReferenceKind.BODY);
      case Handle handle -> addHandle(handle);
      case ConstantDynamic dynamic -> {
        addDescriptor(dynamic.getDescriptor(), ReferenceKind.BODY);
        addHandle(dynamic.getBootstrapMethod());
        for (int index = 0; index < dynamic.getBootstrapMethodArgumentCount(); index++) {
          addConstant(dynamic.getBootstrapMethodArgument(index));
        }
      }
      case null, default -> {}
    }
  }

  /** Collects method metadata and bytecode references. */
  @SuppressWarnings("PMD.TooManyMethods")
  private final class MethodReferenceVisitor extends MethodVisitor {
    private MethodReferenceVisitor() {
      super(Opcodes.ASM9);
    }

    @Override
    public AnnotationVisitor visitAnnotationDefault() {
      return annotationVisitor(ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitAnnotation(final String descriptor, final boolean visible) {
      addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
      return annotationVisitor(ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitTypeAnnotation(
        final int typeRef,
        final TypePath typePath,
        final String descriptor,
        final boolean visible) {
      addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
      return annotationVisitor(ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitInsnAnnotation(
        final int typeRef,
        final TypePath typePath,
        final String descriptor,
        final boolean visible) {
      addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
      return annotationVisitor(ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitTryCatchAnnotation(
        final int typeRef,
        final TypePath typePath,
        final String descriptor,
        final boolean visible) {
      addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
      return annotationVisitor(ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitLocalVariableAnnotation(
        final int typeRef,
        final TypePath typePath,
        final Label[] start,
        final Label[] end,
        final int[] index,
        final String descriptor,
        final boolean visible) {
      addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
      return annotationVisitor(ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitParameterAnnotation(
        final int parameter, final String descriptor, final boolean visible) {
      addDescriptor(descriptor, ReferenceKind.STRUCTURAL);
      return annotationVisitor(ReferenceKind.STRUCTURAL);
    }

    @Override
    public void visitLocalVariable(
        final String name,
        final String descriptor,
        final String signature,
        final Label start,
        final Label end,
        final int index) {
      addDescriptor(descriptor, ReferenceKind.DEBUG_METADATA);
      addSignature(signature, ReferenceKind.DEBUG_METADATA);
    }

    @Override
    public void visitTryCatchBlock(
        final Label start, final Label end, final Label handler, final String type) {
      addInternalName(type, ReferenceKind.STRUCTURAL);
    }

    @Override
    public void visitFrame(
        final int type,
        final int numLocal,
        final Object[] local,
        final int numStack,
        final Object[] stack) {
      addFrameTypes(local, numLocal);
      addFrameTypes(stack, numStack);
    }

    @Override
    public void visitTypeInsn(final int opcode, final String type) {
      if (includeMethodBodies) {
        addInternalName(type, ReferenceKind.BODY);
      }
    }

    @Override
    public void visitFieldInsn(
        final int opcode, final String ownerName, final String fieldName, final String descriptor) {
      if (includeMethodBodies) {
        addInternalName(ownerName, ReferenceKind.BODY);
        addDescriptor(descriptor, ReferenceKind.BODY);
      }
    }

    @Override
    public void visitMethodInsn(
        final int opcode,
        final String ownerName,
        final String methodName,
        final String descriptor,
        final boolean isInterface) {
      if (includeMethodBodies) {
        addInternalName(ownerName, ReferenceKind.BODY);
        addDescriptor(descriptor, ReferenceKind.BODY);
      }
    }

    @Override
    public void visitInvokeDynamicInsn(
        final String name,
        final String descriptor,
        final Handle bootstrapMethodHandle,
        final Object... bootstrapMethodArguments) {
      if (includeMethodBodies) {
        addDescriptor(descriptor, ReferenceKind.BODY);
        addHandle(bootstrapMethodHandle);
        for (final Object argument : bootstrapMethodArguments) {
          addConstant(argument);
        }
      }
    }

    @Override
    public void visitLdcInsn(final Object value) {
      if (includeMethodBodies) {
        addConstant(value);
      }
    }

    @Override
    public void visitMultiANewArrayInsn(final String descriptor, final int dimensions) {
      if (includeMethodBodies) {
        addDescriptor(descriptor, ReferenceKind.BODY);
      }
    }
  }
}
