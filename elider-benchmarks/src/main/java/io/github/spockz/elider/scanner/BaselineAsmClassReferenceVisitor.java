/* WHY: Preserves pre-optimization AsmClassReferenceVisitor verbatim for JMH comparison. */

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

/** Verbatim pre-optimization AsmClassReferenceVisitor. */
@SuppressWarnings({"PMD.GodClass", "PMD.TooManyMethods", "PMD.CommentDefaultAccessModifier"})
final class BaselineAsmClassReferenceVisitor extends ClassVisitor {
  /** Source class identity for diagnostics. */
  private final String sourceClass;

  /** Whether method-body instructions are recorded. */
  private final boolean includeMethodBodies;

  /** Sink receiving internal class names and edge kinds. */
  private final BiConsumer<String, AsmClassReferenceVisitor.ReferenceKind> consumer;

  BaselineAsmClassReferenceVisitor(
      final String sourceClass,
      final boolean includeMethodBodies,
      final BiConsumer<String, AsmClassReferenceVisitor.ReferenceKind> consumer) {
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
    addInternalName(superName, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    if (interfaces != null) {
      for (final String interfaceName : interfaces) {
        addInternalName(interfaceName, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      }
    }
    addSignature(signature, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
  }

  @Override
  public ModuleVisitor visitModule(final String name, final int access, final String version) {
    return new ModuleVisitor(Opcodes.ASM9) {
      @Override
      public void visitMainClass(final String mainClass) {
        addInternalName(mainClass, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      }

      @Override
      public void visitUse(final String service) {
        addInternalName(service, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      }

      @Override
      public void visitProvide(final String service, final String... providers) {
        addInternalName(service, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
        if (providers != null) {
          for (final String provider : providers) {
            addInternalName(provider, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
          }
        }
      }
    };
  }

  @Override
  public void visitOuterClass(final String owner, final String name, final String descriptor) {
    addInternalName(owner, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
  }

  @Override
  public void visitNestHost(final String nestHost) {
    addInternalName(nestHost, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
  }

  @Override
  public void visitNestMember(final String nestMember) {
    addInternalName(nestMember, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
  }

  @Override
  public void visitPermittedSubclass(final String permittedSubclass) {
    addInternalName(permittedSubclass, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
  }

  @Override
  public void visitInnerClass(
      final String name, final String outerName, final String innerName, final int access) {
    addInternalName(name, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    addInternalName(outerName, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
  }

  @Override
  public AnnotationVisitor visitAnnotation(final String descriptor, final boolean visible) {
    addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
  }

  @Override
  public AnnotationVisitor visitTypeAnnotation(
      final int typeRef, final TypePath typePath, final String descriptor, final boolean visible) {
    addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
  }

  @Override
  public FieldVisitor visitField(
      final int access,
      final String name,
      final String descriptor,
      final String signature,
      final Object value) {
    addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    addSignature(signature, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    return new FieldVisitor(Opcodes.ASM9) {
      @Override
      public AnnotationVisitor visitAnnotation(
          final String annotationDescriptor, final boolean visible) {
        addDescriptor(annotationDescriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
        return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(
          final int typeRef,
          final TypePath typePath,
          final String annotationDescriptor,
          final boolean visible) {
        addDescriptor(annotationDescriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
        return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      }
    };
  }

  @Override
  public RecordComponentVisitor visitRecordComponent(
      final String name, final String descriptor, final String signature) {
    addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    addSignature(signature, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    return new RecordComponentVisitor(Opcodes.ASM9) {
      @Override
      public AnnotationVisitor visitAnnotation(
          final String annotationDescriptor, final boolean visible) {
        addDescriptor(annotationDescriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
        return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(
          final int typeRef,
          final TypePath typePath,
          final String annotationDescriptor,
          final boolean visible) {
        addDescriptor(annotationDescriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
        return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
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
    addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    addSignature(signature, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    if (exceptions != null) {
      for (final String exception : exceptions) {
        addInternalName(exception, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      }
    }
    return new MethodReferenceVisitor();
  }

  private AnnotationVisitor annotationVisitor(final AsmClassReferenceVisitor.ReferenceKind kind) {
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

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private void addSignature(
      final String signature, final AsmClassReferenceVisitor.ReferenceKind kind) {
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

  private SignatureVisitor signatureVisitor(final AsmClassReferenceVisitor.ReferenceKind kind) {
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

  private void addDescriptor(
      final String descriptor, final AsmClassReferenceVisitor.ReferenceKind kind) {
    if (descriptor != null) {
      final Type type;
      try {
        type = Type.getType(descriptor);
      } catch (final IllegalArgumentException exception) {
        throw new IllegalArgumentException(
            "Invalid reference descriptor in " + sourceClass + ": " + descriptor, exception);
      }
      if (!validObjectDescriptor(descriptor) || !type.getDescriptor().equals(descriptor)) {
        throw new IllegalArgumentException(
            "Invalid reference descriptor in " + sourceClass + ": " + descriptor);
      }
      addType(type, kind);
    }
  }

  private static boolean validObjectDescriptor(final String descriptor) {
    final int length = descriptor.length();
    int index = 0;
    while (index < length && descriptor.charAt(index) == '[') {
      index++;
    }
    if (index >= length || descriptor.charAt(index) != 'L') {
      return true;
    }
    return length - index >= 3
        && descriptor.charAt(length - 1) == ';'
        && descriptor.indexOf(';', index + 1) == length - 1;
  }

  private void addType(final Type type, final AsmClassReferenceVisitor.ReferenceKind kind) {
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

  private void addInternalName(
      final String name, final AsmClassReferenceVisitor.ReferenceKind kind) {
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
    addInternalName(handle.getOwner(), AsmClassReferenceVisitor.ReferenceKind.BODY);
    addDescriptor(handle.getDesc(), AsmClassReferenceVisitor.ReferenceKind.BODY);
  }

  private void addFrameTypes(final Object[] types, final int count) {
    if (types == null) {
      return;
    }
    for (int index = 0; index < count; index++) {
      if (types[index] instanceof String name) {
        addInternalName(name, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      }
    }
  }

  private void addConstant(final Object value) {
    switch (value) {
      case Type type -> addType(type, AsmClassReferenceVisitor.ReferenceKind.BODY);
      case Handle handle -> addHandle(handle);
      case ConstantDynamic dynamic -> {
        addDescriptor(dynamic.getDescriptor(), AsmClassReferenceVisitor.ReferenceKind.BODY);
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
      return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitAnnotation(final String descriptor, final boolean visible) {
      addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitTypeAnnotation(
        final int typeRef,
        final TypePath typePath,
        final String descriptor,
        final boolean visible) {
      addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitInsnAnnotation(
        final int typeRef,
        final TypePath typePath,
        final String descriptor,
        final boolean visible) {
      addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitTryCatchAnnotation(
        final int typeRef,
        final TypePath typePath,
        final String descriptor,
        final boolean visible) {
      addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
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
      addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitParameterAnnotation(
        final int parameter, final String descriptor, final boolean visible) {
      addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
      return annotationVisitor(AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
    }

    @Override
    public void visitLocalVariable(
        final String name,
        final String descriptor,
        final String signature,
        final Label start,
        final Label end,
        final int index) {
      addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.DEBUG_METADATA);
      addSignature(signature, AsmClassReferenceVisitor.ReferenceKind.DEBUG_METADATA);
    }

    @Override
    public void visitTryCatchBlock(
        final Label start, final Label end, final Label handler, final String type) {
      addInternalName(type, AsmClassReferenceVisitor.ReferenceKind.STRUCTURAL);
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
        addInternalName(type, AsmClassReferenceVisitor.ReferenceKind.BODY);
      }
    }

    @Override
    public void visitFieldInsn(
        final int opcode, final String ownerName, final String fieldName, final String descriptor) {
      if (includeMethodBodies) {
        addInternalName(ownerName, AsmClassReferenceVisitor.ReferenceKind.BODY);
        addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.BODY);
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
        addInternalName(ownerName, AsmClassReferenceVisitor.ReferenceKind.BODY);
        addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.BODY);
      }
    }

    @Override
    public void visitInvokeDynamicInsn(
        final String name,
        final String descriptor,
        final Handle bootstrapMethodHandle,
        final Object... bootstrapMethodArguments) {
      if (includeMethodBodies) {
        addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.BODY);
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
        addDescriptor(descriptor, AsmClassReferenceVisitor.ReferenceKind.BODY);
      }
    }
  }
}
